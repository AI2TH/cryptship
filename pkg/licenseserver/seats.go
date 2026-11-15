package licenseserver

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// ErrSeatLimit means a license already has its maximum number of machines.
var ErrSeatLimit = errors.New("seat limit reached")

// SeatTracker enforces binding.max distinct machines per license. A machine
// holds a seat from its last key request until Lease passes without another
// one, so a retired machine frees its seat on its own.
//
// Seats count the machine fingerprints loaders report. A modified loader can
// report any value, so this is an honest-customer limit, not a cryptographic
// one: every machine that gets the secret can decrypt.
type SeatTracker struct {
	// Lease is how long a seat is held after a machine's last request
	// (default 30 days).
	Lease time.Duration
	// Path, when set, persists seats as JSON so a restart keeps them.
	Path string

	mu     sync.Mutex
	loaded bool
	seats  map[string]map[string]int64 // license id -> machine -> last seen (unix)
}

func (t *SeatTracker) lease() time.Duration {
	if t.Lease <= 0 {
		return 30 * 24 * time.Hour
	}
	return t.Lease
}

// Claim records that machine uses licenseID at now. It fails with
// ErrSeatLimit if max other machines hold live seats. max <= 0 means no limit.
func (t *SeatTracker) Claim(licenseID, machine string, max int, now time.Time) error {
	if max <= 0 {
		return nil
	}
	if machine == "" {
		return fmt.Errorf("%w: the loader sent no machine fingerprint (mount /etc/machine-id)", ErrSeatLimit)
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	t.load()
	m := t.seats[licenseID]
	if m == nil {
		m = map[string]int64{}
		t.seats[licenseID] = m
	}
	cutoff := now.Add(-t.lease()).Unix()
	for id, seen := range m {
		if seen < cutoff {
			delete(m, id)
		}
	}
	if _, ok := m[machine]; !ok && len(m) >= max {
		return fmt.Errorf("%w: license %s is in use on %d machine(s), the maximum", ErrSeatLimit, licenseID, max)
	}
	m[machine] = now.Unix()
	t.save()
	return nil
}

// Release frees machine's seat on licenseID (for example after a machine is
// retired).
func (t *SeatTracker) Release(licenseID, machine string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.load()
	delete(t.seats[licenseID], machine)
	t.save()
}

// InUse returns how many machines hold a live seat on licenseID at now.
func (t *SeatTracker) InUse(licenseID string, now time.Time) int {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.load()
	n, cutoff := 0, now.Add(-t.lease()).Unix()
	for _, seen := range t.seats[licenseID] {
		if seen >= cutoff {
			n++
		}
	}
	return n
}

func (t *SeatTracker) load() {
	if t.loaded {
		return
	}
	t.loaded, t.seats = true, map[string]map[string]int64{}
	if t.Path == "" {
		return
	}
	if b, err := os.ReadFile(t.Path); err == nil {
		if err := json.Unmarshal(b, &t.seats); err != nil || t.seats == nil {
			fmt.Fprintf(os.Stderr, "cryptship-server: WARNING: ignoring unreadable seats file %s: %v\n", t.Path, err)
			t.seats = map[string]map[string]int64{}
		}
	}
}

func (t *SeatTracker) save() {
	if t.Path == "" {
		return
	}
	b, err := json.Marshal(t.seats)
	if err == nil {
		err = writeAtomic(t.Path, b)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "cryptship-server: WARNING: seats not saved to %s: %v\n", t.Path, err)
	}
}

func writeAtomic(path string, data []byte) error {
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
