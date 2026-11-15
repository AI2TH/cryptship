package online

import (
	"bytes"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/AI2TH/cryptship/pkg/crypto"
)

// The attested protocol (the Trustee / KBS pattern):
//
//  1. The loader asks the server for a challenge (POST /v1/challenge). The
//     challenge is single-use, short-lived and MACed by the server, so the
//     server, not the client, decides freshness.
//  2. The loader makes an ephemeral X25519 key pair inside the TEE and asks
//     the attester for evidence whose REPORT_DATA commits to
//     AttestationBinding(license id, challenge, ephemeral public key).
//  3. The server checks the challenge, verifies the evidence against that
//     binding, and returns the binding secret encrypted to the ephemeral key
//     (X25519 + HKDF-SHA256 + AES-256-GCM), signed with the vendor key.
//
// Replaying a captured request fails twice over: the challenge is spent, and
// even a fresh answer is encrypted to an ephemeral key that only the TEE that
// produced the evidence holds.

// ChallengeRequest is POSTed to /v1/challenge.
type ChallengeRequest struct {
	LicenseID string `json:"license_id"`
}

// ChallengeResponse carries an opaque, server-authenticated challenge.
type ChallengeResponse struct {
	Challenge []byte `json:"challenge"`
	NotAfter  int64  `json:"not_after"`
}

// EphemeralKeySize is the size of an X25519 public key.
const EphemeralKeySize = 32

const (
	challengeVersion  = 1
	challengeRandSize = 16
	// ChallengeSize is the encoded size of a challenge token:
	// version (1) || random (16) || expiry (8) || HMAC-SHA256 (32).
	ChallengeSize = 1 + challengeRandSize + 8 + sha256.Size
)

// ErrBadChallenge means a challenge is malformed, forged, for another license,
// or expired.
var ErrBadChallenge = errors.New("online: invalid or expired challenge")

// ChallengeKey derives the server's challenge MAC key from its master secret.
func ChallengeKey(master []byte) ([]byte, error) {
	return hkdf.Key(sha256.New, master, nil, "cryptship/challenge-key/v1", 32)
}

func challengeMAC(key []byte, licenseID string, body []byte) []byte {
	m := hmac.New(sha256.New, key)
	m.Write([]byte("cryptship/challenge/v1\x00"))
	m.Write([]byte(licenseID))
	m.Write([]byte{0})
	m.Write(body)
	return m.Sum(nil)
}

// NewChallenge returns a fresh challenge for licenseID that expires at
// notAfter. It is stateless: the server recognises its own challenges by the
// MAC, and tracks spent ones separately.
func NewChallenge(key []byte, licenseID string, notAfter time.Time) ([]byte, error) {
	body := make([]byte, 1+challengeRandSize, ChallengeSize)
	body[0] = challengeVersion
	if _, err := rand.Read(body[1:]); err != nil {
		return nil, err
	}
	body = binary.BigEndian.AppendUint64(body, uint64(notAfter.Unix()))
	return append(body, challengeMAC(key, licenseID, body)...), nil
}

// CheckChallenge verifies that challenge was issued by the holder of key for
// licenseID and has not expired at now. It does not track reuse.
func CheckChallenge(key []byte, licenseID string, challenge []byte, now time.Time) error {
	if len(challenge) != ChallengeSize || challenge[0] != challengeVersion {
		return ErrBadChallenge
	}
	body, mac := challenge[:ChallengeSize-sha256.Size], challenge[ChallengeSize-sha256.Size:]
	if !hmac.Equal(mac, challengeMAC(key, licenseID, body)) {
		return ErrBadChallenge
	}
	if now.Unix() > int64(binary.BigEndian.Uint64(body[1+challengeRandSize:])) {
		return ErrBadChallenge
	}
	return nil
}

// AttestationBinding is the value attested-mode evidence must commit to (the
// SEV-SNP / TDX REPORT_DATA field): SHA-256 over a domain label, the license
// id, the server's challenge and the loader's ephemeral public key, each
// length-prefixed. Evidence made for another challenge, license or key does
// not verify.
func AttestationBinding(licenseID string, challenge, ephemeralPub []byte) []byte {
	h := sha256.New()
	h.Write([]byte("cryptship/attestation-binding/v2\x00"))
	for _, f := range [][]byte{[]byte(licenseID), challenge, ephemeralPub} {
		var n [4]byte
		binary.BigEndian.PutUint32(n[:], uint32(len(f)))
		h.Write(n[:])
		h.Write(f)
	}
	return h.Sum(nil)
}

const sealInfo = "cryptship/attested-secret/v1"

func sealAAD(licenseID string, challenge []byte) []byte {
	b := append([]byte(sealInfo+"\x00"), licenseID...)
	return append(append(b, 0), challenge...)
}

func sealKey(shared, clientPub, serverPub []byte) ([]byte, error) {
	salt := append(append([]byte{}, clientPub...), serverPub...)
	return hkdf.Key(sha256.New, shared, salt, sealInfo, crypto.KeySize)
}

// SealToEphemeral encrypts secret to the loader's ephemeral X25519 public key.
// It returns the server's one-time public key and the AES-256-GCM ciphertext,
// whose AAD binds the license id and challenge.
func SealToEphemeral(clientPub []byte, licenseID string, challenge, secret []byte) (serverPub, sealed []byte, err error) {
	peer, err := ecdh.X25519().NewPublicKey(clientPub)
	if err != nil {
		return nil, nil, fmt.Errorf("online: bad ephemeral key: %w", err)
	}
	eph, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	shared, err := eph.ECDH(peer) // fails for low-order points
	if err != nil {
		return nil, nil, fmt.Errorf("online: bad ephemeral key: %w", err)
	}
	defer crypto.Wipe(shared)
	serverPub = eph.PublicKey().Bytes()
	key, err := sealKey(shared, clientPub, serverPub)
	if err != nil {
		return nil, nil, err
	}
	defer crypto.Wipe(key)
	sealed, err = crypto.Seal(key, secret, sealAAD(licenseID, challenge))
	return serverPub, sealed, err
}

// OpenFromServer reverses SealToEphemeral with the loader's ephemeral private
// key.
func OpenFromServer(priv *ecdh.PrivateKey, serverPub []byte, licenseID string, challenge, sealed []byte) ([]byte, error) {
	peer, err := ecdh.X25519().NewPublicKey(serverPub)
	if err != nil {
		return nil, fmt.Errorf("online: bad server key: %w", err)
	}
	shared, err := priv.ECDH(peer)
	if err != nil {
		return nil, fmt.Errorf("online: bad server key: %w", err)
	}
	defer crypto.Wipe(shared)
	key, err := sealKey(shared, priv.PublicKey().Bytes(), serverPub)
	if err != nil {
		return nil, err
	}
	defer crypto.Wipe(key)
	secret, err := crypto.Open(key, sealed, sealAAD(licenseID, challenge))
	if err != nil {
		return nil, errors.New("online: sealed secret does not open")
	}
	return secret, nil
}

// AttestedSigningInput is the byte layout the server signs for an attested
// key answer. Every variable-length field is length-prefixed; like the other
// signing inputs it binds signing_key_id.
func AttestedSigningInput(r KeyResponse, clientPub []byte) []byte {
	b := []byte("cryptship/attested-resp/v1\x00")
	for _, f := range [][]byte{[]byte(r.LicenseID), []byte(r.SigningKeyID), r.Nonce, clientPub, r.ServerPub, r.SealedSecret} {
		b = binary.BigEndian.AppendUint32(b, uint32(len(f)))
		b = append(b, f...)
	}
	return binary.BigEndian.AppendUint64(b, uint64(r.NotAfter))
}

// VerifyAttestedKeyResponse decodes an attested key answer and accepts it only
// if it is signed by a key in keys over this license, challenge and ephemeral
// key, carries no plaintext secret, and has not expired at now. The caller
// then opens SealedSecret with OpenFromServer.
func VerifyAttestedKeyResponse(body []byte, keys map[string]ed25519.PublicKey, licenseID string, challenge, clientPub []byte, now time.Time) (KeyResponse, error) {
	var r KeyResponse
	if err := json.Unmarshal(body, &r); err != nil {
		return KeyResponse{}, fmt.Errorf("online: bad response: %w", err)
	}
	if len(r.Sig) == 0 {
		return KeyResponse{}, ErrUnsigned
	}
	pub, err := SigningKey(keys, r.SigningKeyID)
	if err != nil {
		return KeyResponse{}, err
	}
	if !ed25519.Verify(pub, AttestedSigningInput(r, clientPub), r.Sig) {
		return KeyResponse{}, ErrBadSignature
	}
	if r.LicenseID != licenseID || len(challenge) == 0 || !bytes.Equal(r.Nonce, challenge) ||
		len(r.Secret) != 0 || len(r.ServerPub) != EphemeralKeySize || len(r.SealedSecret) == 0 {
		return KeyResponse{}, ErrMismatch
	}
	if r.NotAfter != 0 && now.Unix() > r.NotAfter {
		return KeyResponse{}, ErrExpired
	}
	return r, nil
}
