package crypto

import (
	"crypto/hkdf"
	"crypto/sha256"
)

// Domain-separation labels. Changing any of these is a breaking format change.
const (
	kekInfo = "cryptship/kek/v2" // v2: context-bound
	wrapAAD = "cryptship/wrapped-key/v1"
	blobAAD = "cryptship/payload/v1"
)

// DeriveKEK derives a 32-byte key-encryption key from binding material, a
// per-license salt, and a claims context, using HKDF-SHA256.
//
// Folding the claims context into the KEK means editing a policy-relevant claim
// (expiry, payload id, binding policy, ...) changes the KEK, so the content key
// will not unwrap even if the loader's signature/expiry checks are patched out.
func DeriveKEK(bindingMaterial, salt, context []byte) ([]byte, error) {
	h := sha256.Sum256(context)
	return hkdf.Key(sha256.New, bindingMaterial, salt, kekInfo+"\x00"+string(h[:]), KeySize)
}

// WrapKey encrypts a content key under a KEK.
func WrapKey(kek, contentKey []byte) ([]byte, error) {
	return Seal(kek, contentKey, []byte(wrapAAD))
}

// UnwrapKey reverses WrapKey. A wrong KEK fails the AEAD tag.
func UnwrapKey(kek, wrapped []byte) ([]byte, error) {
	return Open(kek, wrapped, []byte(wrapAAD))
}

// SealPayload encrypts an application payload under the content key, binding the
// per-build payload ID as AAD.
func SealPayload(contentKey, plaintext []byte, payloadID string) ([]byte, error) {
	return Seal(contentKey, plaintext, payloadAAD(payloadID))
}

// OpenPayload reverses SealPayload.
func OpenPayload(contentKey, blob []byte, payloadID string) ([]byte, error) {
	return Open(contentKey, blob, payloadAAD(payloadID))
}

func payloadAAD(payloadID string) []byte {
	return append([]byte(blobAAD+"|"), payloadID...)
}
