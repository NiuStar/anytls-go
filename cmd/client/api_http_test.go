package main

import "testing"

func TestIsHostnameMismatchErrorText(t *testing.T) {
	cases := []struct {
		name  string
		text  string
		match bool
	}{
		{
			name:  "curl no alternative name",
			text:  "SSL: no alternative certificate subject name matches target hostname 'www.google.com'",
			match: true,
		},
		{
			name:  "x509 valid for other domain",
			text:  "x509: certificate is valid for *.facebook.com, facebook.com, not www.google.com",
			match: true,
		},
		{
			name:  "generic timeout",
			text:  "dial tcp: i/o timeout",
			match: false,
		},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			got := isHostnameMismatchErrorText(tc.text)
			if got != tc.match {
				t.Fatalf("unexpected result for %q: got=%v want=%v", tc.text, got, tc.match)
			}
		})
	}
}

func TestDNSProbeServerWeight(t *testing.T) {
	if got, want := dnsProbeServerWeight("1.1.1.1:53"), 5; got != want {
		t.Fatalf("unexpected weight for 1.1.1.1: got=%d want=%d", got, want)
	}
	if got, want := dnsProbeServerWeight("127.0.0.1:53"), 2; got != want {
		t.Fatalf("unexpected weight for 127.0.0.1: got=%d want=%d", got, want)
	}
	if got, want := dnsProbeServerWeight("223.5.5.5:53"), 4; got != want {
		t.Fatalf("unexpected weight for 223.5.5.5: got=%d want=%d", got, want)
	}
}

