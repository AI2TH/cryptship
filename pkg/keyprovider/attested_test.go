package keyprovider

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/AI2TH/cryptship/pkg/attest/attesttest"
	"github.com/AI2TH/cryptship/pkg/crypto"
	"github.com/AI2TH/cryptship/pkg/license"
	"github.com/AI2TH/cryptship/pkg/licenseserver"
)

// recordingClient keeps every /v1/key request and response body.
type recordingClient struct {
	inner         *http.Client
	reqs, answers [][]byte
}

func (r *recordingClient) Do(req *http.Request) (*http.Response, error) {
	var body []byte
	if req.Body != nil {
		body, _ = io.ReadAll(req.Body)
		req.Body = io.NopCloser(bytes.NewReader(body))
	}
	resp, err := r.inner.Do(req)
	if err != nil || !strings.HasSuffix(req.URL.Path, "/v1/key") {
		return resp, err
	}
	ans, _ := io.ReadAll(resp.Body)
	resp.Body = io.NopCloser(bytes.NewReader(ans))
	r.reqs, r.answers = append(r.reqs, body), append(r.answers, ans)
	return resp, nil
}

// TestAttestedReplayIsRefused: an on-path observer who captures a complete,
// genuine attested exchange can neither replay the request nor use the
// answer.
func TestAttestedReplayIsRefused(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	master := make([]byte, 32)
	if _, err := rand.Read(master); err != nil {
		t.Fatal(err)
	}
	contentKey, _ := crypto.RandomKey()
	srv := &licenseserver.Server{Master: master, SignKey: priv, KeyID: "v1", Revoked: map[string]bool{}, Verifier: attesttest.Verifier{}}
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()
	lic := serverBoundLicense(t, priv, master, contentKey, license.BindAttested, ts.URL)

	rec := &recordingClient{inner: ts.Client()}
	got, err := (Attested{Keys: license.KeyRing{"v1": pub}, Client: rec, Attester: attesttest.Attester{}}).ContentKey(context.Background(), lic)
	if err != nil || !bytes.Equal(got, contentKey) {
		t.Fatalf("genuine attested start failed: %v", err)
	}
	if len(rec.reqs) != 1 {
		t.Fatalf("recorded %d key requests", len(rec.reqs))
	}

	// Replay the captured request byte for byte: the challenge is spent.
	resp, err := http.Post(ts.URL+"/v1/key", "application/json", bytes.NewReader(rec.reqs[0]))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("replayed request: status %d, want 403", resp.StatusCode)
	}

	// The captured answer carries no plaintext secret.
	if bytes.Contains(rec.answers[0], []byte(`"secret"`)) {
		t.Fatal("attested answer contains a plaintext secret field")
	}
}

func TestAttestedNeedsVerifierOnServer(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	master := make([]byte, 32)
	contentKey, _ := crypto.RandomKey()
	ts := httptest.NewServer((&licenseserver.Server{Master: master, SignKey: priv, KeyID: "v1"}).Handler())
	defer ts.Close()
	lic := serverBoundLicense(t, priv, master, contentKey, license.BindAttested, ts.URL)
	_, err := (Attested{Keys: license.KeyRing{"v1": pub}, Client: ts.Client(), Attester: attesttest.Attester{}}).ContentKey(context.Background(), lic)
	if !errors.Is(err, ErrDenied) {
		t.Fatalf("server without a verifier: err = %v, want ErrDenied", err)
	}
}
