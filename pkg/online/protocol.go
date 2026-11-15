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
	// Nonce is 16 random bytes for online; for attested it is the server's
	// challenge from /v1/challenge.
	Nonce []byte `json:"nonce"`
	// Attestation carries TEE evidence for the attested flow (empty otherwise).
	// It must commit to AttestationBinding(license_id, nonce, ephemeral_pub).
	Attestation []byte `json:"attestation,omitempty"`
	// EphemeralPub is the loader's one-time X25519 public key (attested only);
	// the server encrypts the secret to it.
	EphemeralPub []byte `json:"ephemeral_pub,omitempty"`
}

// KeyResponse is returned by the server. Sig covers ResponseSigningInput so a
// TLS-terminating proxy cannot forge or replay it.
type KeyResponse struct {
	LicenseID string `json:"license_id"`
	Nonce     []byte `json:"nonce"`
	Secret    []byte `json:"secret,omitempty"` // SecretSize bytes of binding material (online)
	NotAfter  int64  `json:"not_after"`
	// Attested answers carry the secret only encrypted to the loader's
	// ephemeral key (see SealToEphemeral), never in Secret.
	ServerPub    []byte `json:"server_pub,omitempty"`
	SealedSecret []byte `json:"sealed_secret,omitempty"`
	SigningKeyID string `json:"signing_key_id"`
	Sig          []byte `json:"sig"`
}

// DeriveSecret recomputes the per-license binding secret from a master secret.
// The issuer and the server run this identically; nothing secret is stored in
// the license itself.
func DeriveSecret(master []byte, licenseID string) ([]byte, error) {
	return hkdf.Key(sha256.New, master, []byte(licenseID), "cryptship/online-secret/v1", SecretSize)
}

// CheckResponse is the signed answer to a revocation check (GET /v1/check with a
// nonce). Signing the answer stops an on-path attacker or captive portal from
// forging "not revoked": the loader verifies Sig against the vendor key ring and
// that Nonce echoes the one it sent.
type CheckResponse struct {
	LicenseID    string `json:"license_id"`
	Nonce        []byte `json:"nonce"`
	Revoked      bool   `json:"revoked"`
	NotAfter     int64  `json:"not_after"` // how long this answer may be trusted
	SigningKeyID string `json:"signing_key_id"`
	Sig          []byte `json:"sig"`
}

// CheckSigningInput is the fixed byte layout the server signs and the loader
// verifies for a revocation check.
func CheckSigningInput(r CheckResponse) []byte {
	b := []byte("cryptship/revocation-check/v1\x00")
	b = append(b, r.LicenseID...)
	b = append(b, 0)
	b = append(b, r.SigningKeyID...)
	b = append(b, 0)
	b = append(b, r.Nonce...)
	if r.Revoked {
		b = append(b, 1)
	} else {
		b = append(b, 0)
	}
	return binary.BigEndian.AppendUint64(b, uint64(r.NotAfter))
}

// ResponseSigningInput is the fixed byte layout the server signs and the loader
// verifies.
func ResponseSigningInput(r KeyResponse) []byte {
	b := []byte("cryptship/online-resp/v1\x00")
	b = append(b, r.LicenseID...)
	b = append(b, 0)
	b = append(b, r.SigningKeyID...)
	b = append(b, 0)
	b = append(b, r.Nonce...)
	b = append(b, r.Secret...)
	return binary.BigEndian.AppendUint64(b, uint64(r.NotAfter))
}
