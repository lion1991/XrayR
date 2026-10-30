package controller

import (
	"reflect"
	"sync/atomic"
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
	uid, email, ok := parseUserTag(userTag("Snell_0.0.0.0_443", &user, 3))
	if !ok || uid != 42 || email != "a|b@test" {
		t.Fatalf("parseUserTag = %d %q %v, want 42 %q true", uid, email, ok, user.Email)
	}
	if _, _, ok := parseUserTag("not-a-user-tag"); ok {
		t.Fatal("parsed a name without uid")
	}
	if _, _, ok := parseUserTag("Snell_0.0.0.0_443|a@test|42"); ok {
		t.Fatal("parsed a name without credential version")
	}
}

// A changed secret must change the name, or a session authenticated with the
// old secret would keep passing as the user.
func TestUserNamesFollowCredentialChanges(t *testing.T) {
	c := &SingBoxController{credentials: make(map[int]credential)}
	users := []api.UserInfo{{UID: 1, Email: "a@test"}, {UID: 2, Email: "b@test"}}
	names := func(secrets ...string) []string {
		c.trackCredentials(users[:len(secrets)], secrets)
		return c.userNames("Snell_0.0.0.0_443", users[:len(secrets)])
	}
	first := names("p1", "p2")
	if got := names("p1", "p2"); !reflect.DeepEqual(got, first) {
		t.Fatalf("names changed without a secret change: %q -> %q", first, got)
	}
	changed := names("p1", "p2-new")
	if changed[0] != first[0] || changed[1] == first[1] {
		t.Fatalf("names = %q after uid 2 changed its secret, was %q", changed, first)
	}
	// uid 2 leaves and comes back with yet another secret: still a new name.
	names("p1")
	if back := names("p1", "p2-again"); back[1] == first[1] || back[1] == changed[1] {
		t.Fatalf("uid 2 came back as %q, an old name", back[1])
	}
}

type closeRecorder struct{ closed atomic.Bool }

func (r *closeRecorder) Close() error {
	r.closed.Store(true)
	return nil
}

func TestGuardAdmitsOnlyServedUsers(t *testing.T) {
	g := newSingBoxGuard()
	if _, ok := g.admit("a", &closeRecorder{}); ok {
		t.Fatal("admitted a user before any user list")
	}
	if _, ok := g.admit("", &closeRecorder{}); !ok {
		t.Fatal("rejected a connection without user (shared-psk snell)")
	}
	g.admitOnly([]string{"a", "b"})
	connA, connB, gone := &closeRecorder{}, &closeRecorder{}, &closeRecorder{}
	if _, ok := g.admit("a", connA); !ok {
		t.Fatal("rejected served user a")
	}
	if _, ok := g.admit("b", connB); !ok {
		t.Fatal("rejected served user b")
	}
	release, _ := g.admit("b", gone)
	release()

	g.admitOnly([]string{"a"})
	if !connB.closed.Load() {
		t.Fatal("removed user b keeps its connection")
	}
	if connA.closed.Load() || gone.closed.Load() {
		t.Fatal("closed a connection of a served user, or one already released")
	}
	if _, ok := g.admit("b", &closeRecorder{}); ok {
		t.Fatal("removed user b opened a new connection")
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
// rebuild moved the node tag and the secret changed) must arrive as one
// entry or keeper drops one.
func TestTrafficMonitorMergesNamesOfOneUID(t *testing.T) {
	panel := &reportOnlyAPI{}
	c := &SingBoxController{
		config:    &Config{},
		apiClient: panel,
		logger:    log.NewEntry(log.StandardLogger()),
		traffic:   newSingBoxTrafficTracker(nil),
	}
	user := api.UserInfo{UID: 42, Email: "a@test"}
	oldName := userTag("Snell_127.0.0.1_1000", &user, 0)
	newName := userTag("Snell_127.0.0.1_2000", &user, 1)
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
