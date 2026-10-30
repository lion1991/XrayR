package controller

import (
	"context"
	"io"
	"net"
	"net/netip"
	"reflect"
	"sync/atomic"
	"testing"
	"time"

	sbadapter "github.com/sagernet/sing-box/adapter"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/common/uot"
	log "github.com/sirupsen/logrus"
	"golang.org/x/time/rate"

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

var testIP = netip.MustParseAddr("192.0.2.1")

func testGuard() *singBoxGuard {
	return newSingBoxGuard(log.NewEntry(log.StandardLogger()), nil)
}

func admitted(g *singBoxGuard, user string, ip netip.Addr, conn io.Closer) (func(), bool) {
	release, _, err := g.admit(user, ip, conn)
	return release, err == nil
}

func TestGuardAdmitsOnlyServedUsers(t *testing.T) {
	g := testGuard()
	a, b := userTag("n", &api.UserInfo{UID: 1}, 0), userTag("n", &api.UserInfo{UID: 2}, 0)
	if _, ok := admitted(g, a, testIP, &closeRecorder{}); ok {
		t.Fatal("admitted a user before any user list")
	}
	if _, ok := admitted(g, "", testIP, &closeRecorder{}); !ok {
		t.Fatal("rejected a connection without user (shared-psk snell)")
	}
	g.admitOnly([]string{a, b})
	connA, connB, gone := &closeRecorder{}, &closeRecorder{}, &closeRecorder{}
	if _, ok := admitted(g, a, testIP, connA); !ok {
		t.Fatal("rejected served user a")
	}
	if _, ok := admitted(g, b, testIP, connB); !ok {
		t.Fatal("rejected served user b")
	}
	release, _ := admitted(g, b, testIP, gone)
	release()

	g.admitOnly([]string{a})
	if !connB.closed.Load() {
		t.Fatal("removed user b keeps its connection")
	}
	if connA.closed.Load() || gone.closed.Load() {
		t.Fatal("closed a connection of a served user, or one already released")
	}
	if _, ok := admitted(g, b, testIP, &closeRecorder{}); ok {
		t.Fatal("removed user b opened a new connection")
	}
}

// Devices are the IPs seen since the last report, so a device that
// disconnected keeps its slot until the report. A live connection does not
// hold a slot after it (its socket may be dead on a network the phone left),
// but is still reported online.
func TestGuardDeviceLimit(t *testing.T) {
	g := testGuard()
	user := api.UserInfo{UID: 7, DeviceLimit: 2}
	name := userTag("n", &user, 0)
	g.admitOnly([]string{name})
	g.setPolicies(0, []api.UserInfo{user})
	ip := func(s string) netip.Addr { return netip.MustParseAddr(s) }

	releaseA, okA := admitted(g, name, ip("192.0.2.1"), &closeRecorder{})
	releaseB, okB := admitted(g, name, ip("192.0.2.2"), &closeRecorder{})
	if !okA || !okB {
		t.Fatal("rejected a device within the limit")
	}
	if _, ok := admitted(g, name, ip("192.0.2.3"), &closeRecorder{}); ok {
		t.Fatal("admitted a third device over a limit of 2")
	}
	if _, ok := admitted(g, name, ip("192.0.2.1"), &closeRecorder{}); !ok {
		t.Fatal("rejected a second connection from a known device")
	}
	releaseB()
	if _, ok := admitted(g, name, ip("192.0.2.3"), &closeRecorder{}); ok {
		t.Fatal("a device that just disconnected lost its slot before the report")
	}

	want := []api.OnlineUser{{UID: 7, IP: "192.0.2.1"}, {UID: 7, IP: "192.0.2.2"}}
	if got := g.onlineUsers(); !reflect.DeepEqual(got, want) {
		t.Fatalf("online = %+v, want %+v", got, want)
	}
	_, okC := admitted(g, name, ip("192.0.2.3"), &closeRecorder{})
	_, okD := admitted(g, name, ip("192.0.2.4"), &closeRecorder{})
	if !okC || !okD {
		t.Fatal("the live device 192.0.2.1 still holds a slot after the report")
	}
	if _, ok := admitted(g, name, ip("192.0.2.1"), &closeRecorder{}); ok {
		t.Fatal("admitted a third device in the new period")
	}
	want = []api.OnlineUser{{UID: 7, IP: "192.0.2.1"}, {UID: 7, IP: "192.0.2.3"}, {UID: 7, IP: "192.0.2.4"}}
	if got := g.onlineUsers(); !reflect.DeepEqual(got, want) {
		t.Fatalf("online = %+v, want %+v with the long-lived device", got, want)
	}
	releaseA()
}

func TestGuardSpeedLimit(t *testing.T) {
	g := testGuard()
	limited := api.UserInfo{UID: 1, SpeedLimit: 1000}
	free := api.UserInfo{UID: 2}
	names := []string{userTag("n", &limited, 0), userTag("n", &free, 0)}
	g.admitOnly(names)
	g.setPolicies(0, []api.UserInfo{limited, free})

	_, bucket, _ := g.admit(names[0], testIP, &closeRecorder{})
	_, again, _ := g.admit(names[0], testIP, &closeRecorder{})
	if bucket == nil || bucket != again {
		t.Fatal("a limited user's connections do not share one bucket")
	}
	if _, none, _ := g.admit(names[1], testIP, &closeRecorder{}); none != nil {
		t.Fatal("an unlimited user got a bucket")
	}
	// A node limit applies to everyone, the stricter one wins.
	g.setPolicies(500, []api.UserInfo{limited, free})
	if bucket.Limit() != 500 {
		t.Fatalf("limit = %v after a stricter node limit, want 500", bucket.Limit())
	}
	if _, nodeBucket, _ := g.admit(names[1], testIP, &closeRecorder{}); nodeBucket == nil || nodeBucket.Limit() != 500 {
		t.Fatal("the node limit does not apply to a user without one")
	}
	g.setPolicies(0, []api.UserInfo{{UID: 1}, free})
	if bucket.Limit() != rate.Inf {
		t.Fatal("lifting the limit left open connections limited")
	}
}

// One read larger than the burst must still wait its share.
func TestWaitTokensSplitsLargeReads(t *testing.T) {
	bucket := rate.NewLimiter(rate.Limit(10000), 10000)
	start := time.Now()
	waitTokens(bucket, 25000)
	if elapsed := time.Since(start); elapsed < time.Second {
		t.Fatalf("25000 bytes at 10000 B/s with a 10000 burst took %v, want about 1.5s", elapsed)
	}
}

// The copy half-closes a finished direction through CloseWrite; the limiter
// must not turn that into a full close.
func TestRateConnHalfCloses(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	client, err := net.Dial("tcp", listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	server, err := listener.Accept()
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()

	// As in production: the traffic counter below, unwrapped like the copy does.
	counted := newSingBoxTrafficTracker(nil).RoutedConnection(context.Background(), server,
		sbadapter.InboundContext{User: "u"}, nil, nil)
	limited := &rateConn{Conn: counted, bucket: rate.NewLimiter(rate.Inf, 0)}
	writer, _ := N.UnwrapCountWriter(limited, nil)
	closer, ok := N.UnwrapWriter(writer).(N.WriteCloser)
	if !ok {
		t.Fatal("the copy finds no CloseWrite on the limited conn")
	}
	if err := closer.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	if _, err := client.Read(make([]byte, 1)); err != io.EOF {
		t.Fatalf("client read %v after CloseWrite, want EOF", err)
	}
	if _, err := client.Write([]byte("x")); err != nil {
		t.Fatal(err)
	}
	if _, err := limited.Read(make([]byte, 1)); err != nil {
		t.Fatalf("the limited conn cannot read after its CloseWrite: %v", err)
	}
}

func TestAuditTargets(t *testing.T) {
	ip := M.ParseSocksaddr("192.0.2.1:443")
	for _, tc := range []struct {
		metadata sbadapter.InboundContext
		want     []string
	}{
		{sbadapter.InboundContext{Network: "tcp", Destination: ip}, []string{"tcp:192.0.2.1:443"}},
		// Both the dialed address and the sniffed domain, as a client may
		// name an allowed domain while dialing a blocked one.
		{sbadapter.InboundContext{Network: "tcp", Destination: ip, Domain: "example.com"}, []string{"tcp:192.0.2.1:443", "tcp:example.com:443"}},
		{sbadapter.InboundContext{Network: "tcp", Destination: M.ParseSocksaddr("blocked.org:443"), Domain: "example.com"}, []string{"tcp:blocked.org:443", "tcp:example.com:443"}},
		{sbadapter.InboundContext{Network: "tcp", Destination: M.ParseSocksaddr("example.com:443"), Domain: "example.com"}, []string{"tcp:example.com:443"}},
		{sbadapter.InboundContext{Network: "udp", Destination: M.ParseSocksaddr("example.com:53")}, []string{"udp:example.com:53"}},
		{sbadapter.InboundContext{Network: "tcp", Destination: M.ParseSocksaddr("[2001:db8::1]:80")}, []string{"tcp:[2001:db8::1]:80"}},
		{sbadapter.InboundContext{Network: "tcp", Destination: M.SocksaddrFrom(netip.MustParseAddr("::ffff:192.0.2.1"), 80)}, []string{"tcp:192.0.2.1:80"}},
		// UDP over TCP: Domain holds the magic name, the target is in Destination.
		{sbadapter.InboundContext{Network: "udp", Destination: ip, Domain: uot.MagicAddress}, []string{"udp:192.0.2.1:443"}},
		{sbadapter.InboundContext{Network: "udp", Destination: ip, Domain: uot.LegacyMagicAddress}, []string{"udp:192.0.2.1:443"}},
		{sbadapter.InboundContext{Network: "tcp", Destination: M.ParseSocksaddr("Blocked.ORG:80"), Domain: "BLOCKED.Test"}, []string{"tcp:blocked.org:80", "tcp:blocked.test:80"}},
	} {
		if got := auditTargets(&tc.metadata); !reflect.DeepEqual(got, tc.want) {
			t.Errorf("auditTargets = %q, want %q", got, tc.want)
		}
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
		guard:     testGuard(),
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
