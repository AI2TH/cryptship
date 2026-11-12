// Package online defines the wire protocol shared by the online key provider
// (loader side) and the reference license server, so both agree byte-for-byte.
package online

import (
	"crypto/hkdf"
	"crypto/sha256"
	"encoding/binary"
)

// SecretSize is the length of the per-license binding secret.
const SecretSize = 32

// KeyRequest is POSTed by the loader to the server's /v1/key endpoint.
type KeyRequest struct {
	LicenseID string `json:"license_id"`
	Machine   string `json:"machine,omitempty"` // best-effort fingerprint, for seats
	Nonce     []byte `json:"nonce"`             // 16 bytes, anti-replay
	// Attestation carries TEE evidence for the attested flow (empty otherwise).
	Attestation []byte `json:"attestation,omitempty"`
}

// KeyResponse is returned by the server. Sig covers ResponseSigningInput so a
// TLS-terminating proxy cannot forge or replay it.
type KeyResponse struct {
	LicenseID    string `json:"license_id"`
	Nonce        []byte `json:"nonce"`
	Secret       []byte `json:"secret"` // SecretSize bytes of binding material
	NotAfter     int64  `json:"not_after"`
	SigningKeyID string `json:"signing_key_id"`
	Sig          []byte `json:"sig"`
}

// DeriveSecret recomputes the per-license binding secret from a master secret.
// The issuer and the server run this identically; nothing secret is stored in
// the license itself.
func DeriveSecret(master []byte, licenseID string) ([]byte, error) {
	return hkdf.Key(sha256.New, master, []byte(licenseID), "cryptship/online-secret/v1", SecretSize)
}

// ResponseSigningInput is the fixed byte layout the server signs and the loader
// verifies.
func ResponseSigningInput(r KeyResponse) []byte {
	b := []byte("cryptship/online-resp/v1\x00")
	b = append(b, r.LicenseID...)
	b = append(b, 0)
	b = append(b, r.Nonce...)
	b = append(b, r.Secret...)
	return binary.BigEndian.AppendUint64(b, uint64(r.NotAfter))
}
