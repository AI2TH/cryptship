// Package licenseserver is a reference key-broker / license server for the
// online and attested binding modes. It is stateless apart from a denylist and
// an optional attestation verifier: the per-license secret is derived on demand
// from a master secret, so there is no key database to protect.
package licenseserver

import (
	"crypto/ed25519"
	"encoding/json"
	"net/http"
	"time"

	"github.com/AI2TH/cryptship/pkg/attest"
	"github.com/AI2TH/cryptship/pkg/online"
)

// Server answers key requests. Master and SignKey are secret; SignKey's public
// half must be in the loaders' key ring.
type Server struct {
	Master  []byte             // master secret for online.DeriveSecret
	SignKey ed25519.PrivateKey // signs responses
	KeyID   string             // recorded as signing_key_id
	TTL     time.Duration      // validity of each answer (default 24h)
	Revoked map[string]bool    // license_id -> revoked
	// Verifier, when set, must accept the request's attestation evidence for
	// online.AttestationNonce(license_id, nonce) before a secret is released.
	// Nil means attestation is not required: the server cannot tell an
	// attested license from an online one, so a server without a Verifier
	// releases attested-license secrets to anyone who asks.
	Verifier attest.Verifier
}

func (s *Server) ttl() time.Duration {
	if s.TTL == 0 {
		return 24 * time.Hour
	}
	return s.TTL
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
	if s.Revoked[req.LicenseID] {
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

func (s *Server) handleCheck(w http.ResponseWriter, r *http.Request) {
	if s.Revoked[r.URL.Query().Get("license_id")] {
		http.Error(w, "revoked", http.StatusGone)
		return
	}
	w.WriteHeader(http.StatusOK)
}
