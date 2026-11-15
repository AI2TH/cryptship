package main

import (
	"net/http"
	"os"
	"time"

	"github.com/AI2TH/cryptship/pkg/keyprovider"
	"github.com/AI2TH/cryptship/pkg/license"
)

// buildProviders returns the key providers the loader will try, in order. The
// vendor key ring verifies signed server responses (online / attested).
//
// Online outage grace is opt-in: set CRYPTSHIP_ONLINE_GRACE to a duration (e.g.
// "12h") to let a cached, machine-sealed secret ride out a server outage for
// that long. It is off by default (every start needs the server).
func buildProviders(ring license.KeyRing) []keyprovider.Provider {
	httpClient := &http.Client{Timeout: 10 * time.Second}

	var grace time.Duration
	if v := os.Getenv("CRYPTSHIP_ONLINE_GRACE"); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			grace = d
		} else {
			os.Stderr.WriteString("cryptship-loader: WARNING: bad CRYPTSHIP_ONLINE_GRACE, grace disabled: " + err.Error() + "\n")
		}
	}

	return []keyprovider.Provider{
		keyprovider.Offline{},
		keyprovider.Online{Keys: ring, Client: httpClient, CacheDir: stateDir(), Grace: grace},
		keyprovider.Attested{Keys: ring, Client: httpClient, Attester: keyprovider.DefaultAttester()},
	}
}
