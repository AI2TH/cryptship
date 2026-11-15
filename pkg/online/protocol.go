// Package online defines the wire protocol shared by the online key provider
// (loader side) and the reference license server, so both agree byte-for-byte.
package online

import (
	"crypto/hkdf"
	"crypto/sha256"
	"encoding/binary"
	"errors"
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
	// Policy and SecretVersion come from the license (binding.policy,
	// binding.secret_v) and select the server-side derivation. They are not
	// trusted: asking for the wrong one only yields a secret that does not
	// unwrap the license.
	Policy        string `json:"policy,omitempty"`
	SecretVersion int    `json:"secret_v,omitempty"`
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

// DeriveSecret is the legacy (secret version 0) derivation of the per-license
// binding secret: HKDF over the master secret and license id only. The server
// cannot tell an online license from an attested one under it, so a server
// that skips attestation can release attested secrets. Kept so licenses issued
// before secret version 2 keep working; new licenses use DeriveSecretFor.
func DeriveSecret(master []byte, licenseID string) ([]byte, error) {
	return hkdf.Key(sha256.New, master, []byte(licenseID), "cryptship/online-secret/v1", SecretSize)
}

// ErrSecretVersion is returned for an unknown secret version or policy.
var ErrSecretVersion = errors.New("online: unsupported secret version or policy")

// DeriveSecretFor derives the binding secret for a license id, binding policy
// ("online" or "attested") and secret version. Version 2 binds the policy into
// the HKDF info, so the online secret and the attested secret of a license
// differ and an online-only server cannot produce attested secrets. Version 0
// is DeriveSecret, whatever the policy. The issuer and the server run this
// identically; nothing secret is stored in the license.
func DeriveSecretFor(master []byte, licenseID, policy string, version int) ([]byte, error) {
	switch version {
	case 0:
		return DeriveSecret(master, licenseID)
	case 2:
		if policy != "online" && policy != "attested" {
			return nil, ErrSecretVersion
		}
		return hkdf.Key(sha256.New, master, nil, "cryptship/server-secret/v2\x00"+policy+"\x00"+licenseID, SecretSize)
	default:
		return nil, ErrSecretVersion
	}
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
