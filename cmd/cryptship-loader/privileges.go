package main

import (
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
)

// appUser is the identity the application runs as when the loader starts as
// root (CRYPTSHIP_APP_USER). The extracted tree is then owned by a different
// uid (CRYPTSHIP_EXTRACT_OWNER, default root) and the app's group, mode
// 0750/0640: the app can read and run its code but not change it, and no
// other non-root user can read it.
type appUser struct {
	uid, gid int
	owner    int // owner uid of the extracted files
}

// appUserFromEnv parses CRYPTSHIP_APP_USER ("uid" or "uid:gid") and
// CRYPTSHIP_EXTRACT_OWNER. It returns nil when CRYPTSHIP_APP_USER is unset.
// Setting it without running as root is an error, never a silent fallback.
func appUserFromEnv() (*appUser, error) {
	v := os.Getenv("CRYPTSHIP_APP_USER")
	if v == "" {
		return nil, nil
	}
	uidStr, gidStr, hasGid := strings.Cut(v, ":")
	uid, err := parseID(uidStr)
	if err != nil {
		return nil, fmt.Errorf("CRYPTSHIP_APP_USER: %w", err)
	}
	gid := uid
	if hasGid {
		if gid, err = parseID(gidStr); err != nil {
			return nil, fmt.Errorf("CRYPTSHIP_APP_USER: %w", err)
		}
	}
	owner := 0
	if o := os.Getenv("CRYPTSHIP_EXTRACT_OWNER"); o != "" {
		if owner, err = parseID(o); err != nil {
			return nil, fmt.Errorf("CRYPTSHIP_EXTRACT_OWNER: %w", err)
		}
	}
	switch {
	case uid == 0 || gid == 0:
		return nil, errors.New("CRYPTSHIP_APP_USER must name a non-root uid and gid")
	case owner == uid:
		return nil, errors.New("CRYPTSHIP_EXTRACT_OWNER must differ from the app uid, or the app could change its own code")
	case os.Geteuid() != 0:
		return nil, fmt.Errorf("CRYPTSHIP_APP_USER is set, but the loader runs as uid %d; it must start as root to extract as another uid and drop privileges", os.Geteuid())
	}
	return &appUser{uid: uid, gid: gid, owner: owner}, nil
}

func parseID(s string) (int, error) {
	n, err := strconv.Atoi(strings.TrimSpace(s))
	if err != nil || n < 0 || n > 1<<31-2 {
		return 0, fmt.Errorf("bad numeric id %q", s)
	}
	return n, nil
}
