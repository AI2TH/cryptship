// Package licenseserver is a reference key-broker / license server for the
// online and attested binding modes. It is stateless apart from a denylist and
// an optional attestation verifier: the per-license secret is derived on demand
// from a master secret, so there is no key database to protect.
package licenseserver

import (
	"bufio"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/AI2TH/cryptship/pkg/attest"
	"github.com/AI2TH/cryptship/pkg/crypto"
	"github.com/AI2TH/cryptship/pkg/license"
	"github.com/AI2TH/cryptship/pkg/online"
)

// Server answers key requests. Master and SignKey are secret; SignKey's public
// half must be in the loaders' key ring.
type Server struct {
	Master  []byte             // master secret for online.DeriveSecret
	SignKey ed25519.PrivateKey // signs responses
	KeyID   string             // recorded as signing_key_id
	TTL     time.Duration      // validity of each answer (default 24h)
	Revoked map[string]bool    // static denylist: license_id -> revoked
	// RevokedFile, when set, is an additional denylist re-read on each request
	// (one license id per line; blank lines and # comments ignored). Editing it
	// revokes or restores a license WITHOUT restarting the server.
	RevokedFile string
	// Verifier, when set, enables the attested protocol: the request must
	// carry a challenge from /v1/challenge, an ephemeral key, and evidence the
	// Verifier accepts for online.AttestationBinding(license_id, challenge,
	// ephemeral key); the secret is returned encrypted to that key. A server
	// with a Verifier refuses plain (unattested) requests. Nil means the
	// attested protocol is unavailable.
	Verifier attest.Verifier
	// ChallengeTTL is how long a challenge stays valid (default 2 minutes).
	ChallengeTTL time.Duration
	// NoLegacySecrets refuses requests for the legacy (secret version 0)
	// derivation, which does not bind the policy: under it, a server that
	// skips attestation can release an attested license's secret. Set it once
	// every online/attested license in use carries binding.secret_v 2.
	NoLegacySecrets bool

	mu         sync.Mutex
	denyWarned bool // warn once if RevokedFile becomes unreadable

	chalMu sync.Mutex
	spent  map[[32]byte]int64 // challenge hash -> expiry (unix), for single use
}

func (s *Server) challengeTTL() time.Duration {
	if s.ChallengeTTL == 0 {
		return 2 * time.Minute
	}
	return s.ChallengeTTL
}

// spendChallenge checks a challenge and marks it used. Each challenge is
// accepted at most once while this process runs; its expiry bounds reuse
// across a restart.
func (s *Server) spendChallenge(licenseID string, challenge []byte) error {
	key, err := online.ChallengeKey(s.Master)
	if err != nil {
		return err
	}
	now := time.Now()
	if err := online.CheckChallenge(key, licenseID, challenge, now); err != nil {
		return err
	}
	h := sha256.Sum256(challenge)
	s.chalMu.Lock()
	defer s.chalMu.Unlock()
	if s.spent == nil {
		s.spent = map[[32]byte]int64{}
	}
	for k, exp := range s.spent {
		if exp < now.Unix() {
			delete(s.spent, k)
		}
	}
	if _, used := s.spent[h]; used {
		return online.ErrBadChallenge
	}
	s.spent[h] = now.Add(s.challengeTTL()).Unix() + 1
	return nil
}

func (s *Server) ttl() time.Duration {
	if s.TTL == 0 {
		return 24 * time.Hour
	}
	return s.TTL
}

// isRevoked reports whether a license id is denied, by the static map or the
// live RevokedFile. The file is re-read on EVERY call (it is tiny): this is a
// security control, so freshness beats caching — a stale cache could keep
// honouring a just-revoked license (e.g. on a coarse-mtime filesystem).
func (s *Server) isRevoked(id string) bool {
	if s.Revoked[id] {
		return true
	}
	if s.RevokedFile == "" {
		return false
	}
	f, err := os.Open(s.RevokedFile)
	if err != nil {
		s.warnDenyUnreadable(err)
		return false // file-based revocation unavailable; the static map still applies
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if line == id {
			return true
		}
	}
	return false
}

func (s *Server) warnDenyUnreadable(err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.denyWarned {
		fmt.Fprintf(os.Stderr, "cryptship-server: WARNING: revoke-file unreadable, file-based revocation disabled: %v\n", err)
		s.denyWarned = true
	}
}

// Handler exposes POST /v1/key, POST /v1/challenge and GET /v1/check.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/key", s.handleKey)
	mux.HandleFunc("/v1/challenge", s.handleChallenge)
	mux.HandleFunc("/v1/check", s.handleCheck)
	return mux
}

// handleChallenge issues a single-use challenge for the attested protocol.
func (s *Server) handleChallenge(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req online.ChallengeRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4<<10)).Decode(&req); err != nil || req.LicenseID == "" {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	if s.Verifier == nil {
		http.Error(w, "attestation not supported by this server", http.StatusForbidden)
		return
	}
	if s.isRevoked(req.LicenseID) {
		http.Error(w, "revoked", http.StatusGone)
		return
	}
	key, err := online.ChallengeKey(s.Master)
	if err != nil {
		http.Error(w, "server error", http.StatusInternalServerError)
		return
	}
	notAfter := time.Now().Add(s.challengeTTL())
	ch, err := online.NewChallenge(key, req.LicenseID, notAfter)
	if err != nil {
		http.Error(w, "server error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(online.ChallengeResponse{Challenge: ch, NotAfter: notAfter.Unix()})
}

func (s *Server) handleKey(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req online.KeyRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10)).Decode(&req); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	if s.isRevoked(req.LicenseID) {
		http.Error(w, "revoked", http.StatusGone)
		return
	}
	if len(req.EphemeralPub) != 0 {
		s.handleAttestedKey(w, req)
		return
	}
	// A plain request (no attestation protocol) can only ever get an online
	// secret. Under secret version 2 the attested secret differs, so this
	// path cannot release it.
	switch {
	case req.SecretVersion == license.SecretVersion2 && req.Policy != string(license.BindOnline):
		http.Error(w, "attested licenses need the attested protocol", http.StatusForbidden)
		return
	case req.SecretVersion == license.SecretVersionLegacy && (s.NoLegacySecrets || s.Verifier != nil):
		// Legacy secrets do not bind the policy; a server that verifies
		// attestation must not hand them out without it.
		http.Error(w, "legacy secret derivation refused by this server", http.StatusForbidden)
		return
	}
	secret, err := online.DeriveSecretFor(s.Master, req.LicenseID, string(license.BindOnline), req.SecretVersion)
	if err != nil {
		http.Error(w, "unsupported secret version", http.StatusBadRequest)
		return
	}
	defer crypto.Wipe(secret)
	resp := online.KeyResponse{
		LicenseID:    req.LicenseID,
		Nonce:        req.Nonce,
		Secret:       secret,
		NotAfter:     time.Now().Add(s.ttl()).Unix(),
		SigningKeyID: s.KeyID,
	}
	resp.Sig = ed25519.Sign(s.SignKey, online.ResponseSigningInput(resp))
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
}

// handleAttestedKey serves the attested protocol: spend the challenge, verify
// the evidence against the challenge and ephemeral key, and return the secret
// encrypted to that key.
func (s *Server) handleAttestedKey(w http.ResponseWriter, req online.KeyRequest) {
	if s.Verifier == nil {
		http.Error(w, "attestation not supported by this server", http.StatusForbidden)
		return
	}
	if len(req.EphemeralPub) != online.EphemeralKeySize {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	if err := s.spendChallenge(req.LicenseID, req.Nonce); err != nil {
		http.Error(w, "invalid or spent challenge", http.StatusForbidden)
		return
	}
	if _, err := s.Verifier.Verify(req.Attestation, online.AttestationBinding(req.LicenseID, req.Nonce, req.EphemeralPub)); err != nil {
		http.Error(w, "attestation rejected", http.StatusForbidden)
		return
	}
	if req.SecretVersion == license.SecretVersionLegacy && s.NoLegacySecrets {
		http.Error(w, "legacy secret derivation refused by this server", http.StatusForbidden)
		return
	}
	secret, err := online.DeriveSecretFor(s.Master, req.LicenseID, string(license.BindAttested), req.SecretVersion)
	if err != nil {
		http.Error(w, "unsupported secret version", http.StatusBadRequest)
		return
	}
	defer crypto.Wipe(secret)
	serverPub, sealed, err := online.SealToEphemeral(req.EphemeralPub, req.LicenseID, req.Nonce, secret)
	if err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	resp := online.KeyResponse{
		LicenseID:    req.LicenseID,
		Nonce:        req.Nonce,
		NotAfter:     time.Now().Add(s.ttl()).Unix(),
		SigningKeyID: s.KeyID,
		ServerPub:    serverPub,
		SealedSecret: sealed,
	}
	resp.Sig = ed25519.Sign(s.SignKey, online.AttestedSigningInput(resp, req.EphemeralPub))
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
}

// handleCheck answers a revocation check. With a ?nonce= it returns a SIGNED
// online.CheckResponse (200) that the loader verifies, so a captive portal or
// on-path attacker cannot forge "not revoked". Without a nonce it keeps the
// legacy unsigned behaviour (410 revoked / 200 active) for generic clients.
func (s *Server) handleCheck(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("license_id")
	revoked := s.isRevoked(id)

	nonceHex := r.URL.Query().Get("nonce")
	if nonceHex == "" {
		if revoked {
			http.Error(w, "revoked", http.StatusGone)
			return
		}
		w.WriteHeader(http.StatusOK)
		return
	}
	nonce, err := hex.DecodeString(nonceHex)
	if err != nil {
		http.Error(w, "bad nonce", http.StatusBadRequest)
		return
	}
	resp := online.CheckResponse{
		LicenseID: id,
		Nonce:     nonce,
		Revoked:   revoked,
		NotAfter:  time.Now().Add(s.ttl()).Unix(),
	}
	online.SignCheck(s.SignKey, s.KeyID, &resp)
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
}
