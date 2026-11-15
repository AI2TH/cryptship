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

// AttestationNonce is the value attested-mode evidence must commit to (for
// example in the SEV-SNP / TDX REPORT_DATA field): a hash of the license id and
// the request nonce, so evidence made for one request or license does not
// verify for another. The loader's attester and the server's verifier both
// compute it.
func AttestationNonce(licenseID string, nonce []byte) []byte {
	h := sha256.New()
	h.Write([]byte("cryptship/attestation-nonce/v1\x00"))
	h.Write([]byte(licenseID))
	h.Write([]byte{0})
	h.Write(nonce)
	return h.Sum(nil)
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
	b = append(b, r.Nonce...)
	b = append(b, r.Secret...)
	return binary.BigEndian.AppendUint64(b, uint64(r.NotAfter))
}
