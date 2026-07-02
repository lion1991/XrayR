package newV2board_test

import (
	"testing"

	"github.com/XrayR-project/XrayR/api"
	"github.com/XrayR-project/XrayR/api/newV2board"
)

// TestVlessNodeTypeImpliesEnableVless locks in that "Vless" is a first-class
// NodeType: it must enable vless on its own, without the legacy EnableVless
// flag, while the old V2ray+flag form and plain vmess keep their behaviour.
func TestVlessNodeTypeImpliesEnableVless(t *testing.T) {
	cases := []struct {
		nodeType  string
		flag      bool
		wantVless bool
	}{
		{"Vless", false, true},  // new first-class form, no flag needed
		{"vless", false, true},  // case-insensitive
		{"V2ray", true, true},   // legacy form still works
		{"V2ray", false, false}, // plain vmess
		{"Trojan", false, false},
		{"Shadowsocks", false, false},
	}
	for _, tc := range cases {
		t.Run(tc.nodeType, func(t *testing.T) {
			c := newV2board.New(&api.Config{
				APIHost:     "http://127.0.0.1:0",
				Key:         "k",
				NodeID:      1,
				NodeType:    tc.nodeType,
				EnableVless: tc.flag,
			})
			if c.EnableVless != tc.wantVless {
				t.Fatalf("NodeType=%q EnableVless flag=%v -> got EnableVless=%v, want %v",
					tc.nodeType, tc.flag, c.EnableVless, tc.wantVless)
			}
		})
	}
}
