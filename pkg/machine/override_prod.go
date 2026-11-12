//go:build !cryptship_devfp

package machine

// override returns no value in production builds: the CRYPTSHIP_FINGERPRINT
// escape hatch is compiled out so it cannot be used to defeat machine binding.
func override() string { return "" }
