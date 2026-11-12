// Package crypto provides the symmetric primitives cryptship uses to encrypt
// application payloads and to wrap content keys. Everything here is stdlib only
// (AES-256-GCM, HKDF-SHA256) to keep the supply chain minimal.
package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"io"
)

const (
	// KeySize is the size of a content key / KEK in bytes (AES-256).
	KeySize = 32
)

var (
	// ErrKeySize is returned when a key is not KeySize bytes.
	ErrKeySize = errors.New("cryptship/crypto: key must be 32 bytes")
	// ErrShort is returned when a sealed blob is too short to contain a nonce.
	ErrShort = errors.New("cryptship/crypto: ciphertext too short")
)

// Seal encrypts plaintext with AES-256-GCM under key. The returned blob is
// nonce || ciphertext || tag. aad is additional authenticated data that is
// bound to the ciphertext but not encrypted (pass nil if unused).
func Seal(key, plaintext, aad []byte) ([]byte, error) {
	gcm, err := newGCM(key)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}
	// dst=nonce causes Seal to prepend the nonce to its output.
	return gcm.Seal(nonce, nonce, plaintext, aad), nil
}

// Open reverses Seal. It returns ErrShort if the blob is malformed and the
// underlying AEAD error if authentication fails (wrong key or tampering).
func Open(key, blob, aad []byte) ([]byte, error) {
	gcm, err := newGCM(key)
	if err != nil {
		return nil, err
	}
	ns := gcm.NonceSize()
	if len(blob) < ns {
		return nil, ErrShort
	}
	nonce, ct := blob[:ns], blob[ns:]
	return gcm.Open(nil, nonce, ct, aad)
}

// RandomKey returns a fresh cryptographically random content key.
func RandomKey() ([]byte, error) {
	k := make([]byte, KeySize)
	if _, err := io.ReadFull(rand.Reader, k); err != nil {
		return nil, err
	}
	return k, nil
}

// Wipe best-effort zeroes a secret slice. Go's GC may already have copied the
// bytes elsewhere, so this is a hardening measure, not a guarantee.
func Wipe(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

func newGCM(key []byte) (cipher.AEAD, error) {
	if len(key) != KeySize {
		return nil, ErrKeySize
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}
