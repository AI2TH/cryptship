package main

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/AI2TH/cryptship/pkg/crypto"
	"github.com/AI2TH/cryptship/pkg/license"
)

func TestCheckClockDetectsRollback(t *testing.T) {
	dir := t.TempDir()
	key, _ := crypto.RandomKey()
	now := time.Now()
	c := license.Claims{LicenseID: "lic_clock", NotAfter: now.Add(30 * 24 * time.Hour).Unix()}

	if err := checkClock(dir, c, key, now); err != nil {
		t.Fatalf("first start: %v", err)
	}
	// Small step back (NTP correction): allowed.
	if err := checkClock(dir, c, key, now.Add(-time.Hour)); err != nil {
		t.Fatalf("1h back: %v", err)
	}
	// The record keeps the latest time, not the last one.
	if err := checkClock(dir, c, key, now.Add(-clockTolerance-time.Hour)); err == nil || !strings.Contains(err.Error(), "behind") {
		t.Fatalf("rollback past tolerance: err = %v", err)
	}
	// Moving forward is fine and raises the record.
	later := now.Add(10 * 24 * time.Hour)
	if err := checkClock(dir, c, key, later); err != nil {
		t.Fatal(err)
	}
	if err := checkClock(dir, c, key, now); err == nil {
		t.Fatal("rollback below the raised record accepted")
	}
}

func TestCheckClockStateIsSealed(t *testing.T) {
	dir := t.TempDir()
	key, _ := crypto.RandomKey()
	now := time.Now()
	c := license.Claims{LicenseID: "lic_seal", NotAfter: now.Add(time.Hour).Unix()}
	if err := checkClock(dir, c, key, now.Add(48*time.Hour)); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "clock-lic_seal")
	blob, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(blob), strconv.FormatInt(now.Add(48*time.Hour).Unix(), 10)) {
		t.Fatal("state stored in clear")
	}
	// Another license (or build) cannot read or reuse the record.
	other := license.Claims{LicenseID: "lic_other", NotAfter: c.NotAfter}
	if err := os.WriteFile(filepath.Join(dir, "clock-lic_other"), blob, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := checkClock(dir, other, key, now); err != nil {
		t.Fatalf("a record copied from another license must be ignored, got %v", err)
	}
	// Licenses without expiry are not checked and leave no state.
	if err := checkClock(dir, license.Claims{LicenseID: "lic_forever"}, key, now); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir, "clock-lic_forever")); !os.IsNotExist(err) {
		t.Fatal("state written for a license without expiry")
	}
}

func TestCheckClockUnwritableStateDirDoesNotBlock(t *testing.T) {
	// A state dir under a regular file cannot be created, even by root.
	file := filepath.Join(t.TempDir(), "not-a-dir")
	if err := os.WriteFile(file, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	key, _ := crypto.RandomKey()
	now := time.Now()
	c := license.Claims{LicenseID: "lic_ro", NotAfter: now.Add(time.Hour).Unix()}
	if err := checkClock(filepath.Join(file, "state"), c, key, now); err != nil {
		t.Fatalf("unwritable state dir must not stop the loader: %v", err)
	}
}
