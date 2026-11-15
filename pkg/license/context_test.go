package license

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"testing"
)

// goldenClaims sets every field, so the golden vectors below lock the exact
// encoding of both context versions.
func goldenClaims(v int) Claims {
	return Claims{
		Version:      v,
		LicenseID:    "lic_golden",
		CustomerID:   "acme",
		Product:      "widget",
		Edition:      "enterprise",
		PayloadID:    "payload-golden",
		Entitlements: []string{"a", "b"},
		IssuedAt:     1700000000,
		NotAfter:     1800000000,
		Binding: Binding{
			Policy: BindPool, Max: 2, FingerprintHashes: []string{"aa", "bb"},
			Server: "https://x", ProviderData: []byte{1, 2},
		},
		WrappedKeys:   [][]byte{{9, 9}},
		UnboundSecret: []byte{7},
		RevocationURL: "https://r/check",
		SigningKeyID:  "v1",
	}
}

// v1Golden was computed with the BindingContext code before v2 existed. If it
// changes, every v1 license in the field stops unwrapping.
const v1Golden = "6372797074736869702f6b656b2d6374782f76310031006c69635f676f6c64656e0061636d6500776964676574007061796c6f61642d676f6c64656e00706f6f6c00000000006553f100000000006b49d200"

// v2Golden locks the v2 encoding. If it changes, every v2 license stops
// unwrapping: see the comment on Claims before touching the struct. It is
// "cryptship/kek-ctx/v2" NUL SHA-256(v2GoldenJSON), cross-checked outside Go.
const v2Golden = "6372797074736869702f6b656b2d6374782f763200d0c627c281eee2fa7bdbc06fa202632be67eccfd793e3ce49234c074af04864b"

const v2GoldenJSON = `{"v":2,"license_id":"lic_golden","customer_id":"acme","product":"widget","edition":"enterprise",` +
	`"payload_id":"payload-golden","entitlements":["a","b"],"issued_at":1700000000,"not_after":1800000000,` +
	`"binding":{"policy":"pool","max":2,"fingerprint_hashes":["aa","bb"],"server":"https://x","provider_data":"AQI="},` +
	`"wrapped_keys":null,"revocation_url":"https://r/check","signing_key_id":"v1"}`

func mustCtx(t *testing.T, c Claims) []byte {
	t.Helper()
	b, err := c.BindingContext()
	if err != nil {
		t.Fatalf("BindingContext(v%d): %v", c.Version, err)
	}
	return b
}

func TestBindingContextGoldenV1(t *testing.T) {
	if got := hex.EncodeToString(mustCtx(t, goldenClaims(1))); got != v1Golden {
		t.Fatalf("v1 context changed:\n got %s\nwant %s", got, v1Golden)
	}
}

func TestBindingContextGoldenV2(t *testing.T) {
	raw, err := canonicalClaims(goldenClaims(2))
	if err != nil {
		t.Fatal(err)
	}
	if string(raw) != v2GoldenJSON {
		t.Fatalf("canonical claims changed:\n got %s\nwant %s", raw, v2GoldenJSON)
	}
	if got := hex.EncodeToString(mustCtx(t, goldenClaims(2))); got != v2Golden {
		t.Fatalf("v2 context changed:\n got %s\nwant %s", got, v2Golden)
	}
}

func TestBindingContextVersionSelection(t *testing.T) {
	if !bytes.HasPrefix(mustCtx(t, goldenClaims(1)), []byte("cryptship/kek-ctx/v1\x00")) {
		t.Fatal("v1 claims did not get the v1 context")
	}
	if !bytes.HasPrefix(mustCtx(t, goldenClaims(2)), []byte("cryptship/kek-ctx/v2\x00")) {
		t.Fatal("v2 claims did not get the v2 context")
	}
	for _, v := range []int{0, -1, 3, 100} {
		if _, err := goldenClaims(v).BindingContext(); err == nil {
			t.Fatalf("version %d: BindingContext returned no error", v)
		}
	}
}

// Every claim except wrapped_keys and unbound_secret must change the v2
// context. The v1 context, by design, ignores most of them.
func TestBindingContextV2CoversEveryClaim(t *testing.T) {
	mutations := map[string]func(*Claims){
		"v":                          func(c *Claims) { c.Version = 1 },
		"license_id":                 func(c *Claims) { c.LicenseID += "x" },
		"customer_id":                func(c *Claims) { c.CustomerID += "x" },
		"product":                    func(c *Claims) { c.Product += "x" },
		"edition":                    func(c *Claims) { c.Edition = "free" },
		"edition removed":            func(c *Claims) { c.Edition = "" },
		"payload_id":                 func(c *Claims) { c.PayloadID += "x" },
		"entitlements added":         func(c *Claims) { c.Entitlements = append(c.Entitlements, "root") },
		"entitlements removed":       func(c *Claims) { c.Entitlements = nil },
		"entitlements reordered":     func(c *Claims) { c.Entitlements = []string{"b", "a"} },
		"issued_at":                  func(c *Claims) { c.IssuedAt-- },
		"not_after":                  func(c *Claims) { c.NotAfter++ },
		"binding.policy":             func(c *Claims) { c.Binding.Policy = BindStrict },
		"binding.max":                func(c *Claims) { c.Binding.Max = 100 },
		"binding.fingerprint_hashes": func(c *Claims) { c.Binding.FingerprintHashes = []string{"aa"} },
		"binding.server":             func(c *Claims) { c.Binding.Server = "https://evil" },
		"binding.provider_data":      func(c *Claims) { c.Binding.ProviderData = nil },
		"revocation_url changed":     func(c *Claims) { c.RevocationURL = "https://evil/check" },
		"revocation_url removed":     func(c *Claims) { c.RevocationURL = "" },
		"signing_key_id":             func(c *Claims) { c.SigningKeyID = "v2" },
	}
	base := mustCtx(t, goldenClaims(2))
	for name, mutate := range mutations {
		c := goldenClaims(2)
		mutate(&c)
		got, err := c.BindingContext()
		if err == nil && bytes.Equal(got, base) {
			t.Errorf("%s: v2 context unchanged", name)
		}
	}

	// The fields that cannot be known before wrapping are excluded.
	c := goldenClaims(2)
	c.WrappedKeys = [][]byte{{1}, {2}}
	c.UnboundSecret = []byte("other")
	if !bytes.Equal(mustCtx(t, c), base) {
		t.Fatal("wrapped_keys / unbound_secret changed the v2 context")
	}
}

// The mutation table above must name every JSON field of Claims and Binding,
// so a field added later cannot silently escape the test.
func TestBindingContextV2MutationTableIsComplete(t *testing.T) {
	raw, err := json.Marshal(goldenClaims(2))
	if err != nil {
		t.Fatal(err)
	}
	var top map[string]json.RawMessage
	if err := json.Unmarshal(raw, &top); err != nil {
		t.Fatal(err)
	}
	var bind map[string]json.RawMessage
	if err := json.Unmarshal(top["binding"], &bind); err != nil {
		t.Fatal(err)
	}
	want := map[string]bool{"wrapped_keys": true, "unbound_secret": true, "binding": true}
	for _, k := range []string{"v", "license_id", "customer_id", "product", "edition", "payload_id",
		"entitlements", "issued_at", "not_after", "revocation_url", "signing_key_id"} {
		want[k] = true
	}
	for k := range top {
		if !want[k] {
			t.Errorf("claims field %q is not covered by TestBindingContextV2CoversEveryClaim", k)
		}
	}
	for k := range bind {
		switch k {
		case "policy", "max", "fingerprint_hashes", "server", "provider_data":
		default:
			t.Errorf("binding field %q is not covered by TestBindingContextV2CoversEveryClaim", k)
		}
	}
	if len(top) != len(want) {
		t.Errorf("claims has %d fields, the test knows %d", len(top), len(want))
	}
}

// canonicalClaims must not modify the caller's claims.
func TestBindingContextDoesNotMutate(t *testing.T) {
	c := goldenClaims(2)
	_ = mustCtx(t, c)
	if len(c.WrappedKeys) != 1 || len(c.UnboundSecret) != 1 {
		t.Fatal("BindingContext modified the claims")
	}
}

// Re-encoding after a JSON round trip (what the loader does) gives the same
// v2 context as at issue time, including for empty-but-present fields.
func TestBindingContextV2StableAcrossParse(t *testing.T) {
	_, priv := genKey(t)
	for _, c := range []Claims{goldenClaims(2), {Version: 2, LicenseID: "l", PayloadID: "p", Entitlements: []string{}, Binding: Binding{Policy: BindNone}}} {
		lic, err := Sign(priv, c)
		if err != nil {
			t.Fatal(err)
		}
		b, _ := lic.Marshal()
		parsed, err := Parse(b)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(mustCtx(t, c), mustCtx(t, parsed.Claims)) {
			t.Fatalf("context differs after Parse for %+v", c)
		}
	}
}

func TestParseVersionRange(t *testing.T) {
	for v, ok := range map[int]bool{-1: false, 0: false, 1: true, 2: true, 3: false} {
		raw := fmt.Sprintf(`{"claims":{"v":%d,"license_id":"l","payload_id":"p","issued_at":0,"not_after":0,"binding":{"policy":"none"},"wrapped_keys":null,"signing_key_id":""},"sig_alg":"ed25519","sig":""}`, v)
		_, err := Parse([]byte(raw))
		if ok && err != nil {
			t.Errorf("version %d rejected: %v", v, err)
		}
		if !ok && err == nil {
			t.Errorf("version %d accepted", v)
		}
	}
}

func TestSignRefusesWrappedKeysWithoutVersion(t *testing.T) {
	_, priv := genKey(t)
	c := sampleClaims()
	c.Version = 0
	if _, err := Sign(priv, c); err == nil {
		t.Fatal("Sign accepted wrapped keys with no version")
	}
}
