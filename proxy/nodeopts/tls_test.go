package nodeopts

import "testing"

func TestNormalizeAndValidateTLS(t *testing.T) {
	v := true
	in := TLS{
		AllowInsecure: &v,
		CACertPath:    "  /etc/anytls/ca.crt  ",
	}
	got := NormalizeTLS(in)
	if got.CACertPath != "/etc/anytls/ca.crt" {
		t.Fatalf("unexpected ca path: %q", got.CACertPath)
	}
	if got.AllowInsecure == in.AllowInsecure {
		t.Fatalf("allow_insecure pointer should be cloned")
	}
	if err := ValidateTLS(got); err != nil {
		t.Fatalf("validate failed: %v", err)
	}
}

func TestValidateTLSControlChars(t *testing.T) {
	err := ValidateTLS(TLS{CACertPath: "/etc/anytls/\nca.crt"})
	if err == nil {
		t.Fatalf("expect error for control chars")
	}
}

func TestEffectiveAllowInsecure(t *testing.T) {
	if !EffectiveAllowInsecure(nil, true) {
		t.Fatalf("nil should fallback to default=true")
	}
	if EffectiveAllowInsecure(nil, false) {
		t.Fatalf("nil should fallback to default=false")
	}
	f := false
	if EffectiveAllowInsecure(&f, true) {
		t.Fatalf("explicit false should win over default")
	}
}

func TestParseOptionalBool(t *testing.T) {
	if v := ParseOptionalBoolLoose("1"); v == nil || !*v {
		t.Fatalf("parse loose true failed")
	}
	if v := ParseOptionalBoolLoose("0"); v == nil || *v {
		t.Fatalf("parse loose false failed")
	}
	if v, err := ParseOptionalBoolStrict(""); err != nil || v != nil {
		t.Fatalf("empty strict should be nil,nil, got v=%v err=%v", v, err)
	}
	if v, err := ParseOptionalBoolStrict("true"); err != nil || v == nil || !*v {
		t.Fatalf("strict true failed: v=%v err=%v", v, err)
	}
	if _, err := ParseOptionalBoolStrict("maybe"); err == nil {
		t.Fatalf("strict invalid should fail")
	}
}

func TestAllowInsecureModeRoundtrip(t *testing.T) {
	modes := AllowInsecureModeValues()
	if len(modes) != 3 {
		t.Fatalf("unexpected mode count: %d", len(modes))
	}
	if mode := AllowInsecureModeFromPtr(nil); mode != AllowInsecureModeDefault {
		t.Fatalf("nil mode mismatch: %s", mode)
	}
	vTrue := true
	if mode := AllowInsecureModeFromPtr(&vTrue); mode != AllowInsecureModeTrue {
		t.Fatalf("true mode mismatch: %s", mode)
	}
	vFalse := false
	if mode := AllowInsecureModeFromPtr(&vFalse); mode != AllowInsecureModeFalse {
		t.Fatalf("false mode mismatch: %s", mode)
	}

	parsedNil, ok := ParseAllowInsecureMode("")
	if !ok || parsedNil != nil {
		t.Fatalf("empty mode should map to nil")
	}
	parsedTrue, ok := ParseAllowInsecureMode("TRUE")
	if !ok || parsedTrue == nil || !*parsedTrue {
		t.Fatalf("true mode parse failed: %v %v", parsedTrue, ok)
	}
	parsedFalse, ok := ParseAllowInsecureMode("false")
	if !ok || parsedFalse == nil || *parsedFalse {
		t.Fatalf("false mode parse failed: %v %v", parsedFalse, ok)
	}
	if _, ok := ParseAllowInsecureMode("maybe"); ok {
		t.Fatalf("invalid mode should fail")
	}

	if mode := AllowInsecureModeFromBool(true); mode != AllowInsecureModeTrue {
		t.Fatalf("AllowInsecureModeFromBool(true) mismatch: %s", mode)
	}
	if mode := AllowInsecureModeFromBool(false); mode != AllowInsecureModeFalse {
		t.Fatalf("AllowInsecureModeFromBool(false) mismatch: %s", mode)
	}
	if DefaultAllowInsecure {
		t.Fatalf("DefaultAllowInsecure should default to strict certificate verification")
	}
}
