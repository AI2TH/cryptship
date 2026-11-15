package main

import (
	"crypto/hkdf"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"time"

	"github.com/AI2TH/cryptship/pkg/crypto"
	"github.com/AI2TH/cryptship/pkg/license"
)

// clockTolerance is how far the system clock may fall behind the latest time
// the loader has recorded for a license before it refuses to start. It is
// generous so an NTP correction or a restored VM snapshot does not lock a
// customer out.
const clockTolerance = 24 * time.Hour

const clockStateInfo = "cryptship/clock-state/v1"

// checkClock is a best-effort clock-rollback check for licenses that expire.
// It keeps the latest start time seen for the license in the state dir,
// sealed (AES-GCM) under a key derived from the content key, so the file
// cannot be edited to an earlier time without the key. If the clock is now
// more than clockTolerance behind that time, the loader refuses to start.
//
// Limits, by design: deleting the state file (or running with a fresh state
// dir) resets the check, and a state dir that cannot be written disables it
// with a warning. It raises the bar against casually setting the clock back
// to keep an expired license running; for enforced expiry use the online
// provider.
func checkClock(dir string, c license.Claims, contentKey []byte, now time.Time) error {
	if c.NotAfter == 0 {
		return nil // nothing expires, nothing to protect
	}
	key, err := hkdf.Key(sha256.New, contentKey, []byte(c.LicenseID), clockStateInfo, crypto.KeySize)
	if err != nil {
		return err
	}
	defer crypto.Wipe(key)
	aad := []byte(clockStateInfo + "\x00" + c.LicenseID)
	path := filepath.Join(dir, "clock-"+escapeID(c.LicenseID))

	latest := now.Unix()
	switch blob, err := os.ReadFile(path); {
	case err == nil:
		pt, oerr := crypto.Open(key, blob, aad)
		if oerr != nil || len(pt) != 8 {
			warnf("clock state %s is not valid for this license and build; starting it again", path)
			break
		}
		last := int64(binary.BigEndian.Uint64(pt))
		if now.Unix() < last-int64(clockTolerance/time.Second) {
			return fmt.Errorf("system clock (%s) is more than %s behind the latest start recorded for license %s (%s); refusing to start. Correct the clock; the record is %s",
				now.UTC().Format(time.RFC3339), clockTolerance, c.LicenseID, time.Unix(last, 0).UTC().Format(time.RFC3339), path)
		}
		if last > latest {
			latest = last
		}
	case errors.Is(err, fs.ErrNotExist):
	default:
		warnf("clock-rollback check: cannot read %s: %v", path, err)
	}

	var b [8]byte
	binary.BigEndian.PutUint64(b[:], uint64(latest))
	sealed, err := crypto.Seal(key, b[:], aad)
	if err != nil {
		return err
	}
	if err := writeFileAtomic(path, sealed); err != nil {
		warnf("clock-rollback check disabled: cannot write %s: %v", path, err)
	}
	return nil
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

func warnf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "cryptship-loader: WARNING: "+format+"\n", args...)
}
