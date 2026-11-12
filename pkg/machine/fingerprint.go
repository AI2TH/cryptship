// Package machine computes stable identifiers for the host a loader runs on.
//
// Each readable source yields its OWN fingerprint (a Candidate). The loader
// tries every candidate, so a binding survives one source appearing or
// disappearing (root vs non-root, a bind-mounted /etc/machine-id, etc.). This
// is a best-effort, software-only scheme: adequate to stop casual copying, but
// a determined root user can spoof the underlying sources. For strong binding,
// use a TPM- or cloud-identity-backed provider (roadmap).
package machine

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"strings"
)

// EnvOverride pins the fingerprint explicitly. It is honoured ONLY in test
// builds (go build -tags cryptship_devfp); production loaders ignore it, so a
// customer cannot defeat machine binding with `docker run -e`.
const EnvOverride = "CRYPTSHIP_FINGERPRINT"

// ErrNoSource means no usable machine identifier could be read.
var ErrNoSource = errors.New("cryptship/machine: no usable machine identifier is readable (mount /etc/machine-id, or run as root for DMI)")

// Candidate is one independent binding source. ID is what the customer sends to
// the vendor and what the KEK is derived from.
type Candidate struct {
	Source string
	ID     string // hex SHA-256(source-tag || 0x00 || value)
}

// Ordered most-stable first. The hostname is deliberately excluded: inside a
// container it is the container ID and changes on every run.
var sources = []struct{ tag, path string }{
	{"machine-id", "/etc/machine-id"},
	{"dbus-machine-id", "/var/lib/dbus/machine-id"},
	{"dmi-product-uuid", "/sys/class/dmi/id/product_uuid"},
	{"dmi-board-serial", "/sys/class/dmi/id/board_serial"},
}

// Known placeholder firmware values that are not unique to a machine.
var placeholders = map[string]bool{
	"00000000-0000-0000-0000-000000000000": true,
	"03000200-0400-0500-0006-000700080009": true,
	"not specified":                        true,
	"to be filled by o.e.m.":               true,
	"default string":                       true,
	"none":                                 true,
}

// Candidates returns one fingerprint per readable source. Each is independent,
// so gaining or losing another source does not break an existing binding.
func Candidates() ([]Candidate, error) {
	if v := override(); v != "" {
		sum := sha256.Sum256([]byte("override\x00" + v))
		return []Candidate{{Source: EnvOverride, ID: hex.EncodeToString(sum[:])}}, nil
	}
	var out []Candidate
	for _, s := range sources {
		b, err := os.ReadFile(s.path)
		if err != nil {
			continue
		}
		v := strings.TrimSpace(string(b))
		if v == "" || placeholders[strings.ToLower(v)] {
			continue
		}
		sum := sha256.Sum256([]byte(s.tag + "\x00" + v))
		out = append(out, Candidate{Source: s.tag, ID: hex.EncodeToString(sum[:])})
	}
	if len(out) == 0 {
		return nil, ErrNoSource
	}
	return out, nil
}

// ID returns the most stable candidate's fingerprint.
func ID() (string, error) {
	c, err := Candidates()
	if err != nil {
		return "", err
	}
	return c[0].ID, nil
}
