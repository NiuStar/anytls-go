package nodeopts

import (
	"fmt"
	"strings"
	"unicode"
)

type TLS struct {
	AllowInsecure *bool
	CACertPath    string
}

const (
	AllowInsecureModeDefault = "default"
	AllowInsecureModeTrue    = "true"
	AllowInsecureModeFalse   = "false"

	// DefaultAllowInsecure keeps compatibility with legacy AnyTLS behavior.
	DefaultAllowInsecure = true
)

func AllowInsecureModeValues() []string {
	return []string{
		AllowInsecureModeDefault,
		AllowInsecureModeTrue,
		AllowInsecureModeFalse,
	}
}

func AllowInsecureModeFromPtr(v *bool) string {
	if v == nil {
		return AllowInsecureModeDefault
	}
	return AllowInsecureModeFromBool(*v)
}

func AllowInsecureModeFromBool(v bool) string {
	if v {
		return AllowInsecureModeTrue
	}
	return AllowInsecureModeFalse
}

func ParseAllowInsecureMode(mode string) (*bool, bool) {
	switch strings.ToLower(strings.TrimSpace(mode)) {
	case "", AllowInsecureModeDefault:
		return nil, true
	case AllowInsecureModeTrue:
		v := true
		return &v, true
	case AllowInsecureModeFalse:
		v := false
		return &v, true
	default:
		return nil, false
	}
}

func NormalizeTLS(in TLS) TLS {
	in.CACertPath = strings.TrimSpace(in.CACertPath)
	in.AllowInsecure = CloneBoolPtr(in.AllowInsecure)
	return in
}

func ValidateTLS(in TLS) error {
	in = NormalizeTLS(in)
	if hasControlChars(in.CACertPath) {
		return fmt.Errorf("ca_cert_path contains control characters")
	}
	return nil
}

func EffectiveAllowInsecure(v *bool, defaultValue bool) bool {
	if v == nil {
		return defaultValue
	}
	return *v
}

// ParseOptionalBoolLoose parses loose bool texts and returns nil when unsupported.
func ParseOptionalBoolLoose(raw string) *bool {
	raw = strings.TrimSpace(strings.ToLower(raw))
	switch raw {
	case "1", "true", "yes", "on":
		v := true
		return &v
	case "0", "false", "no", "off":
		v := false
		return &v
	default:
		return nil
	}
}

// ParseOptionalBoolStrict parses optional bool flag value.
// Empty raw returns nil,nil; invalid raw returns non-nil error.
func ParseOptionalBoolStrict(raw string) (*bool, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, nil
	}
	v := ParseOptionalBoolLoose(raw)
	if v == nil {
		return nil, fmt.Errorf("invalid bool value %q, expect true/false", raw)
	}
	return v, nil
}

func CloneBoolPtr(v *bool) *bool {
	if v == nil {
		return nil
	}
	out := *v
	return &out
}

func hasControlChars(s string) bool {
	for _, r := range s {
		if r == '\n' || r == '\r' || r == '\t' {
			return true
		}
		if unicode.IsControl(r) {
			return true
		}
	}
	return false
}
