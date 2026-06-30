package newV2board

import (
	"encoding/json"
	"testing"
)

// parseConfig unmarshals a panel /config body into serverConfig and runs the
// vless parser directly — white-box so we exercise the json tags (notably the
// xver fix) without a live panel.
func parseConfig(t *testing.T, body string) (server *serverConfig) {
	t.Helper()
	server = new(serverConfig)
	if err := json.Unmarshal([]byte(body), server); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	return server
}

func TestParseV2rayNodeResponse_RealityPlural(t *testing.T) {
	body := `{
		"server_port": 443,
		"network": "tcp",
		"flow": "xtls-rprx-vision",
		"tls": 2,
		"tls_settings": {
			"server_port": "443",
			"server_names": ["a.example.com", "b.example.com"],
			"short_ids": ["aa", "bb"],
			"private_key": "priv",
			"xver": 1,
			"show": true,
			"min_client_ver": "1.8.0",
			"max_time_diff": 60000,
			"mldsa65_seed": "seed",
			"limit_fallback_upload": {"after_bytes": 1000, "bytes_per_sec": 2000, "burst_bytes_per_sec": 3000}
		}
	}`
	c := &APIClient{NodeType: "Vless", EnableVless: true}
	ni, err := c.parseV2rayNodeResponse(parseConfig(t, body))
	if err != nil {
		t.Fatal(err)
	}
	if !ni.EnableREALITY {
		t.Fatal("EnableREALITY should be true for tls=2")
	}
	r := ni.REALITYConfig
	if got := []string{"a.example.com", "b.example.com"}; !equalStrs(r.ServerNames, got) {
		t.Errorf("ServerNames = %v, want %v", r.ServerNames, got)
	}
	if got := []string{"aa", "bb"}; !equalStrs(r.ShortIds, got) {
		t.Errorf("ShortIds = %v, want %v", r.ShortIds, got)
	}
	// Regression guard: xver was decoded into an UNEXPORTED field before the
	// fix, so it was always 0. It must now round-trip.
	if r.ProxyProtocolVer != 1 {
		t.Errorf("ProxyProtocolVer = %d, want 1 (xver decode regression)", r.ProxyProtocolVer)
	}
	if !r.Show {
		t.Error("Show = false, want true")
	}
	if r.Mldsa65Seed != "seed" {
		t.Errorf("Mldsa65Seed = %q, want seed", r.Mldsa65Seed)
	}
	if r.MinClientVer != "1.8.0" {
		t.Errorf("MinClientVer = %q, want 1.8.0", r.MinClientVer)
	}
	if r.MaxTimeDiff != 60000 {
		t.Errorf("MaxTimeDiff = %d, want 60000", r.MaxTimeDiff)
	}
	// dest falls back to serverNames[0] when no explicit dest is given.
	if r.Dest != "a.example.com:443" {
		t.Errorf("Dest = %q, want a.example.com:443", r.Dest)
	}
	if r.LimitFallbackUpload.AfterBytes != 1000 || r.LimitFallbackUpload.BurstBytesPerSec != 3000 {
		t.Errorf("LimitFallbackUpload = %+v, want {1000,2000,3000}", r.LimitFallbackUpload)
	}
}

func TestParseV2rayNodeResponse_RealityLegacy(t *testing.T) {
	// A node provisioned before the multi-value panel: only singular keys, no xver.
	body := `{
		"server_port": 443,
		"network": "tcp",
		"tls": 2,
		"tls_settings": {
			"server_port": "443",
			"server_name": "legacy.example.com",
			"private_key": "priv",
			"short_id": "sid0"
		}
	}`
	c := &APIClient{NodeType: "Vless", EnableVless: true}
	ni, err := c.parseV2rayNodeResponse(parseConfig(t, body))
	if err != nil {
		t.Fatal(err)
	}
	r := ni.REALITYConfig
	if got := []string{"legacy.example.com"}; !equalStrs(r.ServerNames, got) {
		t.Errorf("ServerNames = %v, want %v (singular wrap)", r.ServerNames, got)
	}
	if got := []string{"sid0"}; !equalStrs(r.ShortIds, got) {
		t.Errorf("ShortIds = %v, want %v (singular wrap)", r.ShortIds, got)
	}
	if r.ProxyProtocolVer != 0 {
		t.Errorf("ProxyProtocolVer = %d, want 0", r.ProxyProtocolVer)
	}
	if r.Dest != "legacy.example.com:443" {
		t.Errorf("Dest = %q, want legacy.example.com:443", r.Dest)
	}
}

func equalStrs(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
