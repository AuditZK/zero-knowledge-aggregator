package main

import "testing"

// CFG-004: in production a benchmark URL must be https AND carry an internal
// token (the series feeds the signed report). An unset URL and development are
// exempt (dev http + tokenless test stacks are allowed).
func TestCheckBenchmarkConfig(t *testing.T) {
	const token = "tok-abcdefghijklmnopqrstuvwx" // ≥24 chars

	cases := []struct {
		name    string
		url     string
		token   string
		isDev   bool
		wantErr bool
	}{
		{"unset url ok", "", "", false, false},
		{"dev http no token ok", "http://api-test.auditzk.com", "", true, false},
		{"dev https no token ok", "https://benchmark.auditzk.com", "", true, false},
		{"prod http rejected", "http://87.106.4.85:8080", token, false, true},
		{"prod https no token rejected", "https://benchmark.auditzk.com", "", false, true},
		{"prod https with token ok", "https://benchmark.auditzk.com", token, false, false},
		{"prod scheme is case-insensitive", "HTTPS://benchmark.auditzk.com", token, false, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := checkBenchmarkConfig(tc.url, tc.token, tc.isDev)
			if (err != nil) != tc.wantErr {
				t.Fatalf("checkBenchmarkConfig(%q, hasToken=%v, dev=%v) err=%v, wantErr=%v",
					tc.url, tc.token != "", tc.isDev, err, tc.wantErr)
			}
		})
	}
}

// CFG-005: the mt-bridge connect call carries the MT investor password in
// cleartext and its signature is only as strong as MT_BRIDGE_HMAC_SECRET, so
// production refuses to boot on an http link or a weak key. An unset URL
// (MetaTrader disabled) and development are exempt.
func TestCheckMTBridgeConfig(t *testing.T) {
	const secret = "mt-abcdefghijklmnopqrstuvwx" // ≥24 chars

	cases := []struct {
		name    string
		url     string
		secret  string
		isDev   bool
		wantErr bool
	}{
		{"unset url ok", "", "", false, false},
		{"dev http no secret ok", "http://mt-bridge:8090", "", true, false},
		{"prod http rejected", "http://mt-bridge:8090", secret, false, true},
		{"prod https no secret rejected", "https://mt-bridge.internal", "", false, true},
		{"prod https short secret rejected", "https://mt-bridge.internal", "tooshort", false, true},
		{"prod https with secret ok", "https://mt-bridge.internal", secret, false, false},
		{"prod scheme is case-insensitive", "HTTPS://mt-bridge.internal", secret, false, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := checkMTBridgeConfig(tc.url, tc.secret, tc.isDev)
			if (err != nil) != tc.wantErr {
				t.Fatalf("checkMTBridgeConfig(%q, secretLen=%d, dev=%v) err=%v, wantErr=%v",
					tc.url, len(tc.secret), tc.isDev, err, tc.wantErr)
			}
		})
	}
}
