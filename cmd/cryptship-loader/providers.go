package main

import (
	"net/http"
	"time"

	"github.com/cryptship/cryptship/pkg/keyprovider"
	"github.com/cryptship/cryptship/pkg/license"
)

// buildProviders returns the key providers the loader will try, in order. The
// vendor key ring verifies signed server responses (online / attested).
func buildProviders(ring license.KeyRing) []keyprovider.Provider {
	httpClient := &http.Client{Timeout: 10 * time.Second}
	return []keyprovider.Provider{
		keyprovider.Offline{},
		keyprovider.Online{Keys: ring, Client: httpClient},
		keyprovider.Attested{Keys: ring, Client: httpClient, Attester: keyprovider.DefaultAttester()},
	}
}
