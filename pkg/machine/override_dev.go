//go:build cryptship_devfp

package machine

import "os"

// override honours CRYPTSHIP_FINGERPRINT in test/dev builds only
// (go build -tags cryptship_devfp), for exercising strict/pool binding without
// real hardware.
func override() string { return os.Getenv(EnvOverride) }
