package license

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"testing"
)

// FuzzParse: Parse never panics; whatever it accepts round-trips through
// Marshal, has a supported version, and never verifies under an unrelated key.
func FuzzParse(f *testing.F) {
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	other, _, _ := ed25519.GenerateKey(rand.Reader)
	for _, c := range []Claims{
		{Version: FormatVersion, LicenseID: "lic", PayloadID: "p", SigningKeyID: "v1", Binding: Binding{Policy: BindNone}, UnboundSecret: make([]byte, 32), WrappedKeys: [][]byte{{1, 2}}},
		{Version: FormatVersion1, LicenseID: "lic", PayloadID: "p", Binding: Binding{Policy: BindOnline, Server: "https://k", Max: 3, SecretVersion: SecretVersion2}, WrappedKeys: [][]byte{{1}}},
	} {
		lic, err := Sign(priv, c)
		if err != nil {
			f.Fatal(err)
		}
		b, _ := lic.Marshal()
		f.Add(b)
	}
	f.Add([]byte(`{"claims":{"v":99},"sig_alg":"ed25519","sig":""}`))
	f.Add([]byte(`{"claims":null}`))
	f.Add([]byte(`{"claims":{"v":2,"extra":1}}`))

	f.Fuzz(func(t *testing.T, data []byte) {
		lic, err := Parse(data)
		if err != nil {
			return
		}
		if lic.Claims.Version < FormatVersion1 || lic.Claims.Version > FormatVersion {
			t.Fatalf("accepted version %d", lic.Claims.Version)
		}
		_, _ = lic.Claims.BindingContext()
		_ = lic.Claims.Validate()
		_ = lic.Claims.Expired(0)
		if lic.Verify(other) == nil {
			t.Fatal("verified under an unrelated key")
		}
		b, err := lic.Marshal()
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		again, err := Parse(b)
		if err != nil {
			t.Fatalf("re-parse of marshalled license: %v", err)
		}
		// encoding/json compacts raw claims, so whitespace in hand-written
		// claims is not preserved; compact claims must survive byte for byte.
		var compact bytes.Buffer
		if json.Compact(&compact, lic.ClaimsRaw) == nil && bytes.Equal(compact.Bytes(), lic.ClaimsRaw) &&
			(!bytes.Equal(again.ClaimsRaw, lic.ClaimsRaw) || !bytes.Equal(again.Sig, lic.Sig)) {
			t.Fatalf("round trip changed the signed bytes:\n%s\n%s", lic.ClaimsRaw, again.ClaimsRaw)
		}
	})
}
