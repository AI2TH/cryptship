package main

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"time"

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
	st := sealedState{info: clockStateInfo, licenseID: c.LicenseID, path: filepath.Join(dir, "clock-"+escapeID(c.LicenseID))}

	latest := now.Unix()
	switch last, err := st.read(contentKey); {
	case err == nil:
		if now.Unix() < last-int64(clockTolerance/time.Second) {
			return fmt.Errorf("system clock (%s) is more than %s behind the latest start recorded for license %s (%s); refusing to start. Correct the clock; the record is %s",
				now.UTC().Format(time.RFC3339), clockTolerance, c.LicenseID, time.Unix(last, 0).UTC().Format(time.RFC3339), st.path)
		}
		if last > latest {
			latest = last
		}
	case errors.Is(err, fs.ErrNotExist):
	case errors.Is(err, errBadState):
		warnf("clock state %s is not valid for this license and build; starting it again", st.path)
	default:
		warnf("clock-rollback check: cannot read %s: %v", st.path, err)
	}

	if err := st.write(contentKey, latest); err != nil {
		warnf("clock-rollback check disabled: cannot write %s: %v", st.path, err)
	}
	return nil
}

func warnf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "cryptship-loader: WARNING: "+format+"\n", args...)
}
