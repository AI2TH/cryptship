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

	"github.com/cryptship/cryptship/pkg/online"
)

// Server answers key requests. Master and SignKey are secret; SignKey's public
// half must be in the loaders' key ring.
type Server struct {
	Master  []byte             // master secret for online.DeriveSecret
	SignKey ed25519.PrivateKey // signs responses
	KeyID   string             // recorded as signing_key_id
	TTL     time.Duration      // validity of each answer (default 24h)
	Revoked map[string]bool    // license_id -> revoked
	// Verify, when set, must return nil for the request's attestation evidence
	// before a secret is released (attested mode). Nil = attestation not required.
	Verify func(evidence []byte) error
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
	if s.Verify != nil {
		if err := s.Verify(req.Attestation); err != nil {
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
