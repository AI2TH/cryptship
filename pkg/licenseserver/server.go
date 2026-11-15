// Package licenseserver is a reference key-broker / license server for the
// online and attested binding modes. It is stateless apart from a denylist and
// an optional attestation verifier: the per-license secret is derived on demand
// from a master secret, so there is no key database to protect.
package licenseserver

import (
	"bufio"
	"crypto/ed25519"
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
	// Verifier, when set, must accept the request's attestation evidence for
	// online.AttestationNonce(license_id, nonce) before a secret is released.
	// Nil means attestation is not required: the server cannot tell an attested
	// license from an online one, so a server without a Verifier releases
	// attested-license secrets to anyone who asks.
	Verifier attest.Verifier

	mu         sync.Mutex
	denyWarned bool // warn once if RevokedFile becomes unreadable
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

// Handler exposes POST /v1/key and GET /v1/check.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/key", s.handleKey)
	mux.HandleFunc("/v1/check", s.handleCheck)
	return mux
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
	if s.Verifier != nil {
		if _, err := s.Verifier.Verify(req.Attestation, online.AttestationNonce(req.LicenseID, req.Nonce)); err != nil {
			http.Error(w, "attestation rejected", http.StatusForbidden)
			return
		}
	}
	secret, err := online.DeriveSecret(s.Master, req.LicenseID)
	if err != nil {
		http.Error(w, "server error", http.StatusInternalServerError)
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
		LicenseID:    id,
		Nonce:        nonce,
		Revoked:      revoked,
		NotAfter:     time.Now().Add(s.ttl()).Unix(),
		SigningKeyID: s.KeyID,
	}
	resp.Sig = ed25519.Sign(s.SignKey, online.CheckSigningInput(resp))
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
}
