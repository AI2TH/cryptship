package crypto

import (
	"bytes"
	"testing"
)

func mustKey(t *testing.T) []byte {
	t.Helper()
	k, err := RandomKey()
	if err != nil {
		t.Fatalf("RandomKey: %v", err)
	}
	if len(k) != KeySize {
		t.Fatalf("RandomKey len = %d, want %d", len(k), KeySize)
	}
	return k
}

func TestSealOpenRoundTrip(t *testing.T) {
	key := mustKey(t)
	pt := []byte("hello cryptship, this is plaintext")
	aad := []byte("some-aad")

	blob, err := Seal(key, pt, aad)
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	if bytes.Contains(blob, pt) {
		t.Fatalf("ciphertext contains plaintext")
	}
	got, err := Open(key, blob, aad)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if !bytes.Equal(got, pt) {
		t.Fatalf("round trip mismatch: got %q want %q", got, pt)
	}

	// Two seals of the same input must differ (fresh nonce each time).
	blob2, err := Seal(key, pt, aad)
	if err != nil {
		t.Fatalf("Seal#2: %v", err)
	}
	if bytes.Equal(blob, blob2) {
		t.Fatalf("two Seal calls produced identical output (nonce reuse?)")
	}
}

func TestOpenFailsOnFlippedByte(t *testing.T) {
	key := mustKey(t)
	pt := []byte("integrity matters")
	blob, err := Seal(key, pt, nil)
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	// Flip a byte in the ciphertext body (past the 12-byte nonce, before the tag).
	bad := append([]byte(nil), blob...)
	bad[12] ^= 0x01
	if _, err := Open(key, bad, nil); err == nil {
		t.Fatalf("Open accepted a tampered ciphertext")
	}
	// Flip a byte in the tag.
	bad = append([]byte(nil), blob...)
	bad[len(bad)-1] ^= 0x80
	if _, err := Open(key, bad, nil); err == nil {
		t.Fatalf("Open accepted a tampered tag")
	}
	// Wrong AAD must fail too.
	if _, err := Open(key, blob, []byte("other-aad")); err == nil {
		t.Fatalf("Open accepted mismatched AAD")
	}
	// Wrong key must fail.
	if _, err := Open(mustKey(t), blob, nil); err == nil {
		t.Fatalf("Open accepted the wrong key")
	}
}

func TestOpenRejectsShortAndBadKeySize(t *testing.T) {
	key := mustKey(t)
	if _, err := Open(key, []byte("short"), nil); err != ErrShort {
		t.Fatalf("Open(short) err = %v, want ErrShort", err)
	}
	if _, err := Seal([]byte("too-short-key"), []byte("x"), nil); err != ErrKeySize {
		t.Fatalf("Seal(bad key) err = %v, want ErrKeySize", err)
	}
}

func TestWrapUnwrapRoundTrip(t *testing.T) {
	kek := mustKey(t)
	contentKey := mustKey(t)

	wrapped, err := WrapKey(kek, contentKey)
	if err != nil {
		t.Fatalf("WrapKey: %v", err)
	}
	got, err := UnwrapKey(kek, wrapped)
	if err != nil {
		t.Fatalf("UnwrapKey: %v", err)
	}
	if !bytes.Equal(got, contentKey) {
		t.Fatalf("unwrapped key mismatch")
	}
	// A different KEK must not unwrap.
	if _, err := UnwrapKey(mustKey(t), wrapped); err == nil {
		t.Fatalf("UnwrapKey succeeded with the wrong KEK")
	}
	// A wrapped key is sealed with the wrap AAD, so a plain Open with nil AAD
	// must not succeed (domain separation).
	if _, err := Open(kek, wrapped, nil); err == nil {
		t.Fatalf("wrapped key opened without the wrap AAD")
	}
}

func TestDeriveKEKDeterministicAndDistinct(t *testing.T) {
	binding := []byte("fingerprint-A")
	salt := []byte("lic_0001")
	ctx := []byte("ctx-1")

	k1, err := DeriveKEK(binding, salt, ctx)
	if err != nil {
		t.Fatalf("DeriveKEK: %v", err)
	}
	k2, err := DeriveKEK(binding, salt, ctx)
	if err != nil {
		t.Fatalf("DeriveKEK#2: %v", err)
	}
	if len(k1) != KeySize {
		t.Fatalf("KEK len = %d, want %d", len(k1), KeySize)
	}
	if !bytes.Equal(k1, k2) {
		t.Fatalf("DeriveKEK not deterministic for equal inputs")
	}

	kB, err := DeriveKEK([]byte("fingerprint-B"), salt, ctx)
	if err != nil {
		t.Fatalf("DeriveKEK(B): %v", err)
	}
	if bytes.Equal(k1, kB) {
		t.Fatalf("different binding material produced the same KEK")
	}

	kS, err := DeriveKEK(binding, []byte("lic_0002"), ctx)
	if err != nil {
		t.Fatalf("DeriveKEK(salt2): %v", err)
	}
	if bytes.Equal(k1, kS) {
		t.Fatalf("different salt produced the same KEK")
	}

	kC, err := DeriveKEK(binding, salt, []byte("ctx-2"))
	if err != nil {
		t.Fatalf("DeriveKEK(ctx2): %v", err)
	}
	if bytes.Equal(k1, kC) {
		t.Fatalf("different claims context produced the same KEK")
	}
}

func TestSealOpenPayloadBoundToPayloadID(t *testing.T) {
	key := mustKey(t)
	pt := []byte("tar bytes")
	blob, err := SealPayload(key, pt, "build-1")
	if err != nil {
		t.Fatalf("SealPayload: %v", err)
	}
	got, err := OpenPayload(key, blob, "build-1")
	if err != nil || !bytes.Equal(got, pt) {
		t.Fatalf("OpenPayload round trip failed: %v", err)
	}
	if _, err := OpenPayload(key, blob, "build-2"); err == nil {
		t.Fatalf("OpenPayload accepted a different payload id")
	}
}
