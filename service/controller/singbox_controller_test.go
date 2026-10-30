package controller

import (
	"strings"
	"testing"

	"github.com/XrayR-project/XrayR/api"
)

func TestUserSecrets(t *testing.T) {
	secrets, err := userSecrets("anytls", []api.UserInfo{
		{UID: 1, Passwd: "p1", UUID: "u1"},
		{UID: 2, UUID: "u2"},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if secrets[0] != "p1" || secrets[1] != "u2" {
		t.Fatalf("secrets = %v, want password first, uuid as fallback", secrets)
	}

	// sing-anytls and sing-quic keep the later of two users sharing a
	// password, which would bill one user's traffic to the other.
	_, err = userSecrets("anytls", []api.UserInfo{
		{UID: 1, Passwd: "same"},
		{UID: 2, UUID: "same"},
	})
	if err == nil || !strings.Contains(err.Error(), "users 1 and 2") {
		t.Fatalf("duplicate secret: err = %v, want users 1 and 2 named", err)
	}

	_, err = userSecrets("anytls", []api.UserInfo{{UID: 3}})
	if err == nil {
		t.Fatal("empty secret: want error")
	}
}
