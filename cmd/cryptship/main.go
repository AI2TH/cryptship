// Command cryptship is the vendor-side tool: generate signing keys and a server
// master secret, read a machine fingerprint, pack (optionally compile, then
// encrypt) an application payload, issue signed licenses, and inspect them.
package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/cryptship/cryptship/pkg/archive"
	"github.com/cryptship/cryptship/pkg/crypto"
	"github.com/cryptship/cryptship/pkg/license"
	"github.com/cryptship/cryptship/pkg/machine"
	"github.com/cryptship/cryptship/pkg/online"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case "keygen":
		err = cmdKeygen(os.Args[2:])
	case "master-key":
		err = cmdMasterKey(os.Args[2:])
	case "fingerprint":
		err = cmdFingerprint(os.Args[2:])
	case "pack":
		err = cmdPack(os.Args[2:])
	case "issue":
		err = cmdIssue(os.Args[2:])
	case "inspect":
		err = cmdInspect(os.Args[2:])
	case "-h", "--help", "help":
		usage()
		return
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n\n", os.Args[1])
		usage()
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprint(os.Stderr, `cryptship — ship encrypted, license-gated container payloads

usage:
  cryptship keygen       --out-priv vendor.key --out-pub vendor.pub [--key-id v1] [--force]
  cryptship master-key   --out master.key
  cryptship fingerprint  [--all]
  cryptship pack         --in APPDIR --out payload.enc [--key-out content.key] [--transform-cmd CMD]
  cryptship issue        --priv vendor.key --content-key content.key --meta payload.json \
                         --customer NAME --product NAME --binding none|strict|pool|online|attested [options] --out license.json
  cryptship inspect      [--pub vendor.pub] license.json
`)
}

// ---- keygen ----

func cmdKeygen(args []string) error {
	fs := flag.NewFlagSet("keygen", flag.ExitOnError)
	outPriv := fs.String("out-priv", "vendor.key", "output path for private signing key")
	outPub := fs.String("out-pub", "vendor.pub", "output path for public verification key")
	keyID := fs.String("key-id", "v1", "identifier recorded in licenses for key rotation")
	force := fs.Bool("force", false, "overwrite an existing private key")
	fs.Parse(args)

	if !*force {
		if _, err := os.Stat(*outPriv); err == nil {
			return fmt.Errorf("keygen: %s already exists (use --force to overwrite)", *outPriv)
		}
	}
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	if err := writeB64(*outPriv, priv, 0o600); err != nil {
		return err
	}
	if err := writeB64(*outPub, pub, 0o644); err != nil {
		return err
	}
	fmt.Printf("wrote private key %s (keep secret)\n", *outPriv)
	fmt.Printf("wrote public key  %s (ship in image)\n", *outPub)
	fmt.Printf("signing key id:   %s\n", *keyID)
	return nil
}

// ---- master-key ----

func cmdMasterKey(args []string) error {
	fs := flag.NewFlagSet("master-key", flag.ExitOnError)
	out := fs.String("out", "master.key", "output path for the server master secret")
	fs.Parse(args)
	k, err := crypto.RandomKey()
	if err != nil {
		return err
	}
	if err := writeB64(*out, k, 0o600); err != nil {
		return err
	}
	fmt.Printf("wrote master key %s (keep secret; used by cryptship-server and `issue --server-master-key`)\n", *out)
	return nil
}

// ---- fingerprint ----

func cmdFingerprint(args []string) error {
	fs := flag.NewFlagSet("fingerprint", flag.ExitOnError)
	all := fs.Bool("all", false, "print one fingerprint per readable source (not just the most stable)")
	fs.Parse(args)
	cands, err := machine.Candidates()
	if err != nil {
		return err
	}
	if *all {
		for _, c := range cands {
			fmt.Printf("%-18s %s\n", c.Source, c.ID)
		}
		return nil
	}
	fmt.Println(cands[0].ID)
	return nil
}

// ---- pack ----

type payloadMeta struct {
	PayloadID string `json:"payload_id"`
	CreatedAt int64  `json:"created_at"`
	Bytes     int    `json:"plaintext_bytes"`
}

func cmdPack(args []string) error {
	fs := flag.NewFlagSet("pack", flag.ExitOnError)
	in := fs.String("in", "", "application directory to encrypt (required)")
	out := fs.String("out", "payload.enc", "output path for the encrypted payload")
	keyOut := fs.String("key-out", "content.key", "output path for the content key (keep secret)")
	metaOut := fs.String("meta-out", "", "output path for build metadata (default <out>.json)")
	transform := fs.String("transform-cmd", "", "shell command run over a copy of --in before encrypting (e.g. compile to bytecode / Nuitka); $CRYPTSHIP_SRC is the dir")
	fs.Parse(args)

	if *in == "" {
		return errors.New("pack: --in is required")
	}
	if *metaOut == "" {
		*metaOut = *out + ".json"
	}

	srcDir := *in
	if *transform != "" {
		staged, err := runTransform(*in, *transform)
		if err != nil {
			return err
		}
		defer os.RemoveAll(filepath.Dir(staged))
		srcDir = staged
	}
	tarBytes, err := archive.TarDir(srcDir)
	if err != nil {
		return fmt.Errorf("pack: tar %s: %w", srcDir, err)
	}
	contentKey, err := crypto.RandomKey()
	if err != nil {
		return err
	}
	payloadID := randHex(16)
	blob, err := crypto.SealPayload(contentKey, tarBytes, payloadID)
	if err != nil {
		return err
	}
	if err := os.WriteFile(*out, blob, 0o644); err != nil {
		return err
	}
	if err := writeB64(*keyOut, contentKey, 0o600); err != nil {
		return err
	}
	meta := payloadMeta{PayloadID: payloadID, CreatedAt: time.Now().Unix(), Bytes: len(tarBytes)}
	mb, _ := json.MarshalIndent(meta, "", "  ")
	if err := os.WriteFile(*metaOut, mb, 0o644); err != nil {
		return err
	}
	fmt.Printf("payload:    %s (%d bytes encrypted)\n", *out, len(blob))
	fmt.Printf("content key:%s (keep secret, feed to `issue`)\n", *keyOut)
	fmt.Printf("meta:       %s\n", *metaOut)
	fmt.Printf("payload id: %s\n", payloadID)
	return nil
}

// ---- issue ----

func cmdIssue(args []string) error {
	fs := flag.NewFlagSet("issue", flag.ExitOnError)
	privPath := fs.String("priv", "vendor.key", "vendor private signing key")
	keyID := fs.String("key-id", "v1", "signing key id to record in the license")
	keyPath := fs.String("content-key", "content.key", "content key produced by `pack`")
	metaPath := fs.String("meta", "", "build metadata from `pack` (for payload id)")
	payloadID := fs.String("payload-id", "", "payload id (alternative to --meta)")
	licID := fs.String("license-id", "", "license id (default random)")
	customer := fs.String("customer", "", "customer id/name (required)")
	product := fs.String("product", "", "product name (required)")
	edition := fs.String("edition", "", "edition/tier")
	expires := fs.String("expires", "", "expiry date YYYY-MM-DD")
	days := fs.Int("days", 0, "expiry as N days from now (alternative to --expires)")
	binding := fs.String("binding", "", "binding policy: none|strict|pool|online|attested (required)")
	server := fs.String("server", "", "license/key-broker server URL (online/attested binding)")
	masterPath := fs.String("server-master-key", "", "server master secret (online/attested), from `cryptship master-key`")
	revURL := fs.String("revocation-url", "", "optional revocation check URL")
	out := fs.String("out", "license.json", "output license path")
	var fps stringList
	fs.Var(&fps, "fingerprint", "bound machine fingerprint (repeatable; strict=1, pool>=1)")
	var ents stringList
	fs.Var(&ents, "entitlement", "entitlement string (repeatable)")
	fs.Parse(args)

	if *customer == "" || *product == "" {
		return errors.New("issue: --customer and --product are required")
	}
	if *binding == "" {
		return errors.New("issue: --binding is required (none|strict|pool|online|attested)")
	}

	priv, err := readB64(*privPath)
	if err != nil {
		return fmt.Errorf("issue: read private key: %w", err)
	}
	contentKey, err := readB64(*keyPath)
	if err != nil {
		return fmt.Errorf("issue: read content key: %w", err)
	}

	pid := *payloadID
	if pid == "" && *metaPath != "" {
		var m payloadMeta
		if err := readJSON(*metaPath, &m); err != nil {
			return fmt.Errorf("issue: read meta: %w", err)
		}
		pid = m.PayloadID
	}
	if pid == "" {
		return errors.New("issue: payload id required (use --meta or --payload-id)")
	}

	lid := *licID
	if lid == "" {
		lid = "lic_" + randHex(8)
	}
	notAfter, err := resolveExpiry(*expires, *days)
	if err != nil {
		return err
	}

	var master []byte
	if *binding == string(license.BindOnline) || *binding == string(license.BindAttested) {
		if *server == "" || *masterPath == "" {
			return errors.New("issue: online/attested binding needs --server and --server-master-key")
		}
		if master, err = readB64(*masterPath); err != nil {
			return fmt.Errorf("issue: read master key: %w", err)
		}
	}

	claims := license.Claims{
		Version:       license.FormatVersion,
		LicenseID:     lid,
		CustomerID:    *customer,
		Product:       *product,
		Edition:       *edition,
		PayloadID:     pid,
		Entitlements:  ents,
		IssuedAt:      time.Now().Unix(),
		NotAfter:      notAfter,
		RevocationURL: *revURL,
		SigningKeyID:  *keyID,
	}

	if err := wrapInto(&claims, license.BindingPolicy(*binding), contentKey, fps, *server, master); err != nil {
		return err
	}
	if err := claims.Validate(); err != nil {
		return fmt.Errorf("issue: %w", err)
	}

	lic, err := license.Sign(ed25519.PrivateKey(priv), claims)
	if err != nil {
		return err
	}
	b, err := lic.Marshal()
	if err != nil {
		return err
	}
	if err := os.WriteFile(*out, b, 0o644); err != nil {
		return err
	}
	fmt.Printf("issued %s for %s/%s (binding=%s) -> %s\n", lid, *customer, *product, *binding, *out)
	if notAfter != 0 {
		fmt.Printf("expires: %s\n", time.Unix(notAfter, 0).UTC().Format("2006-01-02"))
	}
	return nil
}

func wrapInto(c *license.Claims, policy license.BindingPolicy, contentKey []byte, fps []string, server string, master []byte) error {
	switch policy {
	case license.BindNone:
		secret, err := crypto.RandomKey()
		if err != nil {
			return err
		}
		c.Binding = license.Binding{Policy: license.BindNone}
		c.UnboundSecret = secret
		return wrapWith(c, secret, contentKey)

	case license.BindStrict:
		if len(fps) != 1 {
			return errors.New("issue: strict binding needs exactly one --fingerprint")
		}
		c.Binding = license.Binding{Policy: policy, Max: 1}
		return wrapPerFingerprint(c, contentKey, fps)

	case license.BindPool:
		if len(fps) < 1 {
			return errors.New("issue: pool binding needs at least one --fingerprint")
		}
		c.Binding = license.Binding{Policy: policy, Max: len(fps)}
		return wrapPerFingerprint(c, contentKey, fps)

	case license.BindOnline, license.BindAttested:
		if server == "" || len(master) == 0 {
			return errors.New("issue: online/attested binding needs --server and --server-master-key")
		}
		c.Binding = license.Binding{Policy: policy, Server: server}
		secret, err := online.DeriveSecret(master, c.LicenseID)
		if err != nil {
			return err
		}
		return wrapWith(c, secret, contentKey)

	default:
		return fmt.Errorf("issue: unknown binding policy %q", policy)
	}
}

// wrapWith derives the KEK (binding material + claims context) and appends one
// wrapped content key.
func wrapWith(c *license.Claims, material, contentKey []byte) error {
	kek, err := crypto.DeriveKEK(material, []byte(c.LicenseID), c.BindingContext())
	if err != nil {
		return err
	}
	wk, err := crypto.WrapKey(kek, contentKey)
	if err != nil {
		return err
	}
	c.WrappedKeys = append(c.WrappedKeys, wk)
	return nil
}

func wrapPerFingerprint(c *license.Claims, contentKey []byte, fps []string) error {
	for _, fp := range fps {
		kek, err := crypto.DeriveKEK([]byte(fp), []byte(c.LicenseID), c.BindingContext())
		if err != nil {
			return err
		}
		wk, err := crypto.WrapKey(kek, contentKey)
		if err != nil {
			return err
		}
		c.WrappedKeys = append(c.WrappedKeys, wk)
		h := sha256.Sum256([]byte(fp))
		c.Binding.FingerprintHashes = append(c.Binding.FingerprintHashes, hex.EncodeToString(h[:]))
	}
	return nil
}

// ---- inspect ----

func cmdInspect(args []string) error {
	fs := flag.NewFlagSet("inspect", flag.ExitOnError)
	pubPath := fs.String("pub", "", "public key / key ring to verify the signature (optional)")
	fs.Parse(args)
	if fs.NArg() < 1 {
		return errors.New("inspect: give a license file")
	}
	b, err := os.ReadFile(fs.Arg(0))
	if err != nil {
		return err
	}
	lic, err := license.Parse(b)
	if err != nil {
		return err
	}
	c := lic.Claims
	fmt.Printf("license id:   %s\n", c.LicenseID)
	fmt.Printf("customer:     %s\n", c.CustomerID)
	fmt.Printf("product:      %s  edition=%s\n", c.Product, c.Edition)
	fmt.Printf("payload id:   %s\n", c.PayloadID)
	fmt.Printf("entitlements: %s\n", strings.Join(c.Entitlements, ", "))
	fmt.Printf("issued:       %s\n", tsStr(c.IssuedAt))
	fmt.Printf("expires:      %s\n", tsStr(c.NotAfter))
	fmt.Printf("binding:      %s (max=%d, keys=%d)", c.Binding.Policy, c.Binding.Max, len(c.WrappedKeys))
	if c.Binding.Server != "" {
		fmt.Printf("  server=%s", c.Binding.Server)
	}
	fmt.Println()
	fmt.Printf("signing key:  %s  alg=%s\n", c.SigningKeyID, lic.SigAlg)
	fmt.Printf("expired now:  %v\n", c.Expired(time.Now().Unix()))

	if *pubPath != "" {
		rb, err := os.ReadFile(*pubPath)
		if err != nil {
			return err
		}
		ring, err := license.ParseKeyRing(rb)
		if err != nil {
			return err
		}
		if err := lic.VerifyWith(ring); err != nil {
			fmt.Printf("signature:    INVALID (%v)\n", err)
			return err
		}
		fmt.Printf("signature:    valid\n")
	}
	return nil
}

// ---- helpers ----

type stringList []string

func (s *stringList) String() string { return strings.Join(*s, ",") }
func (s *stringList) Set(v string) error {
	*s = append(*s, v)
	return nil
}

func resolveExpiry(date string, days int) (int64, error) {
	if date != "" {
		t, err := time.Parse("2006-01-02", date)
		if err != nil {
			return 0, fmt.Errorf("issue: bad --expires: %w", err)
		}
		return t.Unix(), nil
	}
	if days > 0 {
		return time.Now().AddDate(0, 0, days).Unix(), nil
	}
	return 0, nil
}

func tsStr(u int64) string {
	if u == 0 {
		return "(none)"
	}
	return time.Unix(u, 0).UTC().Format(time.RFC3339)
}

func randHex(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func writeB64(path string, data []byte, mode os.FileMode) error {
	return os.WriteFile(path, []byte(base64.StdEncoding.EncodeToString(data)+"\n"), mode)
}

func readB64(path string) ([]byte, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return base64.StdEncoding.DecodeString(strings.TrimSpace(string(b)))
}

func readJSON(path string, v any) error {
	b, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	return json.Unmarshal(b, v)
}

// runTransform copies the app into a temp staging dir, runs the transform
// command there ($CRYPTSHIP_SRC = staging dir), and returns the staged dir to be
// encrypted — so a memory dump of the running app yields compiled artifacts
// rather than clean source. The command uses the operator's toolchain, keeping
// cryptship's core language-agnostic.
func runTransform(in, command string) (string, error) {
	staging, err := os.MkdirTemp("", "cryptship-pack-")
	if err != nil {
		return "", err
	}
	app := filepath.Join(staging, "app")
	if err := copyTree(in, app); err != nil {
		os.RemoveAll(staging)
		return "", fmt.Errorf("pack: stage source: %w", err)
	}
	fmt.Printf("transform:  %s\n", command)
	cmd := exec.Command("sh", "-c", command)
	cmd.Dir = app
	cmd.Env = append(os.Environ(), "CRYPTSHIP_SRC="+app)
	cmd.Stdout, cmd.Stderr = os.Stderr, os.Stderr
	if err := cmd.Run(); err != nil {
		os.RemoveAll(staging)
		return "", fmt.Errorf("pack: transform failed: %w", err)
	}
	return app, nil
}

func copyTree(src, dst string) error {
	return filepath.Walk(src, func(p string, fi os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(src, p)
		if err != nil {
			return err
		}
		target := filepath.Join(dst, rel)
		switch {
		case fi.IsDir():
			return os.MkdirAll(target, fi.Mode().Perm()|0o700)
		case fi.Mode()&os.ModeSymlink != 0:
			link, err := os.Readlink(p)
			if err != nil {
				return err
			}
			return os.Symlink(link, target)
		default:
			if err := os.MkdirAll(filepath.Dir(target), 0o700); err != nil {
				return err
			}
			b, err := os.ReadFile(p)
			if err != nil {
				return err
			}
			return os.WriteFile(target, b, fi.Mode().Perm())
		}
	})
}
