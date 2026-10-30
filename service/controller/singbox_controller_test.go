package controller

import (
	"reflect"
	"testing"

	log "github.com/sirupsen/logrus"

	"github.com/XrayR-project/XrayR/api"
)

func TestValidUsers(t *testing.T) {
	valid, secrets, skipped := validUsers([]api.UserInfo{
		{UID: 1, Passwd: "p1", UUID: "u1"},
		{UID: 2, UUID: "u2"},
		{UID: 3},                   // no secret
		{UID: 2, UUID: "u2-again"}, // uid listed twice
		// sing-anytls and sing-quic keep the later of two users sharing a
		// secret, which would bill one user's traffic to the other.
		{UID: 4, Passwd: "same"},
		{UID: 5, UUID: "same"},
	})
	var uids []int
	for _, user := range valid {
		uids = append(uids, user.UID)
	}
	if !reflect.DeepEqual(uids, []int{1, 2}) || !reflect.DeepEqual(secrets, []string{"p1", "u2"}) {
		t.Fatalf("valid = %v, secrets = %v, want uids [1 2] with password first and uuid as fallback", uids, secrets)
	}
	if len(skipped) != 3 {
		t.Fatalf("skipped = %q, want one reason each for uid 3, the second uid 2 and the shared secret", skipped)
	}
}

func TestParseUserTag(t *testing.T) {
	user := api.UserInfo{UID: 42, Email: "a|b@test"}
	uid, email, ok := parseUserTag(userTag("Snell_0.0.0.0_443", &user))
	if !ok || uid != 42 || email != "a|b@test" {
		t.Fatalf("parseUserTag = %d %q %v, want 42 %q true", uid, email, ok, user.Email)
	}
	if _, _, ok := parseUserTag("not-a-user-tag"); ok {
		t.Fatal("parsed a name without uid")
	}
}

type reportOnlyAPI struct {
	api.API
	reports [][]api.UserTraffic
}

func (r *reportOnlyAPI) ReportUserTraffic(traffic *[]api.UserTraffic) error {
	r.reports = append(r.reports, append([]api.UserTraffic(nil), *traffic...))
	return nil
}

// keeper keys a report by uid, so a uid counted under two names (here: a
// rebuild moved the node tag) must arrive as one entry or keeper drops one.
func TestTrafficMonitorMergesNamesOfOneUID(t *testing.T) {
	panel := &reportOnlyAPI{}
	c := &SingBoxController{
		config:    &Config{},
		apiClient: panel,
		logger:    log.NewEntry(log.StandardLogger()),
		traffic:   newSingBoxTrafficTracker(nil),
	}
	user := api.UserInfo{UID: 42, Email: "a@test"}
	oldName := userTag("Snell_127.0.0.1_1000", &user)
	newName := userTag("Snell_127.0.0.1_2000", &user)
	c.traffic.counter(oldName).up.Add(3)
	c.traffic.counter(newName).up.Add(4)
	c.traffic.counter(newName).down.Add(5)

	if err := c.trafficMonitor(); err != nil {
		t.Fatal(err)
	}
	want := [][]api.UserTraffic{{{UID: 42, Email: "a@test", Upload: 7, Download: 5}}}
	if !reflect.DeepEqual(panel.reports, want) {
		t.Fatalf("reports = %+v, want %+v", panel.reports, want)
	}
	if c.traffic.counter(oldName).up.Load() != 0 || c.traffic.counter(newName).down.Load() != 0 {
		t.Fatal("reported traffic was not subtracted from the counters")
	}
}
