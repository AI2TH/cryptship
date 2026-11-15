package main

import (
	"crypto/hkdf"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"os"
	"path/filepath"

	"github.com/AI2TH/cryptship/pkg/crypto"
)

// Loader state (the revocation-grace and clock-rollback records) is a single
// timestamp per license, sealed with AES-256-GCM so it cannot be edited or
// moved between licenses without the key. Each record kind has its own key and
// AAD, both derived from the per-license secret the caller passes in.

// errBadState means a state record exists but does not open under this
// license's key (edited, copied from another license, or an older format).
var errBadState = errors.New("state record is not valid for this license")

// sealedState names one kind of sealed per-license timestamp record.
type sealedState struct {
	info      string // HKDF info and AAD prefix, e.g. "cryptship/clock-state/v1"
	licenseID string
	path      string
}

func (s sealedState) key(secret []byte) ([]byte, error) {
	return hkdf.Key(sha256.New, secret, []byte(s.licenseID), s.info, crypto.KeySize)
}

func (s sealedState) aad() []byte { return []byte(s.info + "\x00" + s.licenseID) }

// read returns the sealed timestamp. A missing file returns an error that
// satisfies errors.Is(err, fs.ErrNotExist); a record that does not open
// returns errBadState.
func (s sealedState) read(secret []byte) (int64, error) {
	blob, err := os.ReadFile(s.path)
	if err != nil {
		return 0, err
	}
	key, err := s.key(secret)
	if err != nil {
		return 0, err
	}
	defer crypto.Wipe(key)
	pt, err := crypto.Open(key, blob, s.aad())
	if err != nil || len(pt) != 8 {
		return 0, errBadState
	}
	return int64(binary.BigEndian.Uint64(pt)), nil
}

// write seals t and replaces the record atomically.
func (s sealedState) write(secret []byte, t int64) error {
	key, err := s.key(secret)
	if err != nil {
		return err
	}
	defer crypto.Wipe(key)
	var b [8]byte
	binary.BigEndian.PutUint64(b[:], uint64(t))
	sealed, err := crypto.Seal(key, b[:], s.aad())
	if err != nil {
		return err
	}
	return writeFileAtomic(s.path, sealed)
}

// writeFileAtomic writes via a temp file and rename, so a crash never leaves
// a truncated state file.
func writeFileAtomic(path string, data []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".tmp-"+filepath.Base(path)+"-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}
