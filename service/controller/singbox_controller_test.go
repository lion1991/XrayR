package controller

import (
	"context"
	"encoding/base64"
	"errors"
	"io"
	"net"
	"net/netip"
	"reflect"
	"sync/atomic"
	"testing"
	"time"

	sbadapter "github.com/sagernet/sing-box/adapter"
	sbc "github.com/sagernet/sing-box/constant"
	sboption "github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/buf"
	"github.com/sagernet/sing/common/json/badoption"
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
	}, nodeSecret(&api.NodeInfo{NodeType: "AnyTLS"}))
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
		for i, secret := range secrets {
			users[i].Passwd = secret
		}
		c.trackCredentials(users[:len(secrets)])
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

func TestAutoSpeedLimit(t *testing.T) {
	a := newAutoSpeedLimit(&AutoSpeedLimitConfig{Limit: 10, WarnTimes: 1, LimitSpeed: 2, LimitDuration: 1}, log.NewEntry(log.StandardLogger()))
	start := time.Now()
	period := 10 * time.Second
	fast := api.UserTraffic{UID: 1, Download: 20e6} // 2 MB/s, over 10 Mbps
	slow := api.UserTraffic{UID: 2, Upload: 1e6}
	tick := func(n int, traffic ...api.UserTraffic) (map[int]uint64, bool) {
		return a.observe(start.Add(time.Duration(n)*period), period, traffic)
	}
	if _, changed := tick(1, fast, slow); changed {
		t.Fatal("limited at the first warning, WarnTimes is 1")
	}
	if _, changed := tick(2, slow); changed {
		t.Fatal("limited after a slow report")
	}
	tick(3, fast)
	limits, changed := tick(4, fast, slow)
	if !changed || !reflect.DeepEqual(limits, map[int]uint64{1: 250000}) {
		t.Fatalf("limits = %v, changed %v after two fast reports in a row, want uid 1 at 2 Mbps", limits, changed)
	}
	if _, changed := tick(5, fast); changed {
		t.Fatal("a limited user was limited again")
	}
	// The speed is measured over the time counted, not the nominal period.
	if a.observe(start.Add(6*period), 100*time.Second, []api.UserTraffic{{UID: 3, Download: 20e6}}); a.warned[3] != 0 {
		t.Fatal("measured a long period as a short one")
	}
	if limits, changed := tick(12, slow); !changed || len(limits) != 0 {
		t.Fatalf("limits = %v, changed %v after the minute, want lifted", limits, changed)
	}
	if newAutoSpeedLimit(&AutoSpeedLimitConfig{Limit: 10}, nil) != nil || newAutoSpeedLimit(nil, nil) != nil {
		t.Fatal("auto limiting on without a limit speed or config")
	}
}

// A connection opened unlimited cannot be slowed down, so it is cut once its
// user gets a limit; connections in the user's bucket just follow the rate.
func TestGuardCutsUnlimitedConnectionsOnNewLimit(t *testing.T) {
	g := testGuard()
	users := []api.UserInfo{{UID: 1}, {UID: 2}, {UID: 3, SpeedLimit: 1000}}
	var names []string
	for i := range users {
		names = append(names, userTag("n", &users[i], 0))
	}
	g.admitOnly(names)
	g.setPolicies(0, users)
	open := make([]*closeRecorder, len(users))
	buckets := make([]*rate.Limiter, len(users))
	for i := range users {
		open[i] = &closeRecorder{}
		_, buckets[i], _ = g.admit(names[i], testIP, open[i])
	}

	g.setAutoLimits(map[int]uint64{1: 500, 3: 2000})
	if !open[0].closed.Load() {
		t.Fatal("an unlimited connection kept going after its user was auto limited")
	}
	if open[1].closed.Load() || open[2].closed.Load() {
		t.Fatal("cut a user without a new limit, or one already in a bucket")
	}
	if buckets[2].Limit() != 1000 {
		t.Fatalf("limit = %v, auto limiting loosened the panel's 1000", buckets[2].Limit())
	}
	if _, bucket, _ := g.admit(names[0], testIP, &closeRecorder{}); bucket == nil || bucket.Limit() != 500 {
		t.Fatal("a new connection of the auto limited user is not limited")
	}

	// The panel giving a limit cuts the same way.
	users[1].SpeedLimit = 3000
	g.setPolicies(0, users)
	if !open[1].closed.Load() {
		t.Fatal("an unlimited connection kept going after the panel limited its user")
	}
	g.setAutoLimits(nil)
	if buckets[2].Limit() != 1000 {
		t.Fatal("lifting the auto limit did not restore the panel's")
	}
}

// A client retrying against a limit gets one log line per reason a minute.
func TestGuardThrottlesRejectionLogs(t *testing.T) {
	g := testGuard()
	if !g.shouldLog("device|1") || g.shouldLog("device|1") {
		t.Fatal("logged a repeated rejection, or not the first")
	}
	if !g.shouldLog("device|2") || !g.shouldLog("audit|1|7") {
		t.Fatal("throttled another user's or reason's rejection")
	}
	g.rejectLogged["device|1"] = time.Now().Add(-rejectLogEvery)
	if !g.shouldLog("device|1") {
		t.Fatal("still throttled after the minute")
	}
}

func TestDomainStrategy(t *testing.T) {
	for _, test := range []struct {
		enableDNS bool
		dnsType   string
		want      uint8
	}{
		{false, "UseIPv4", sbc.DomainStrategyAsIS},
		{true, "", sbc.DomainStrategyAsIS},
		{true, "AsIs", sbc.DomainStrategyAsIS},
		{true, "UseIP", sbc.DomainStrategyAsIS},
		{true, "UseIPv4", sbc.DomainStrategyIPv4Only},
		{true, "useipv6", sbc.DomainStrategyIPv6Only},
		{true, "UseIPv4v6", sbc.DomainStrategyPreferIPv4},
		{true, "ForceIPv6v4", sbc.DomainStrategyPreferIPv6},
	} {
		got, err := domainStrategy(&Config{EnableDNS: test.enableDNS, DNSType: test.dnsType})
		if err != nil || got != sboption.DomainStrategy(test.want) {
			t.Errorf("EnableDNS %v, DNSType %q: got %v, %v; want %v", test.enableDNS, test.dnsType, got, err, test.want)
		}
	}
	if _, err := domainStrategy(&Config{EnableDNS: true, DNSType: "UseIPv5"}); err == nil {
		t.Error("an unknown DNSType must stop the node from starting")
	}
}

func TestDirectOptionsBindsSendIP(t *testing.T) {
	for _, test := range []struct {
		sendIP     string
		inet4      string
		inet6      string
		wantsError bool
	}{
		{sendIP: ""},
		{sendIP: "0.0.0.0"},
		{sendIP: "::"},
		{sendIP: "203.0.113.7", inet4: "203.0.113.7"},
		{sendIP: "::ffff:203.0.113.7", inet4: "203.0.113.7"},
		{sendIP: "2001:db8::7", inet6: "2001:db8::7"},
		{sendIP: "example.com", wantsError: true},
	} {
		c := &SingBoxController{config: &Config{SendIP: test.sendIP}}
		options, err := c.directOptions(sboption.DomainStrategy(sbc.DomainStrategyIPv4Only))
		if (err != nil) != test.wantsError {
			t.Errorf("SendIP %q: error %v", test.sendIP, err)
			continue
		}
		show := func(addr *badoption.Addr) string {
			if addr == nil {
				return ""
			}
			return netip.Addr(*addr).String()
		}
		if inet4, inet6 := show(options.Inet4BindAddress), show(options.Inet6BindAddress); inet4 != test.inet4 || inet6 != test.inet6 {
			t.Errorf("SendIP %q: binds %q and %q, want %q and %q", test.sendIP, inet4, inet6, test.inet4, test.inet6)
		}
		if !test.wantsError && options.DomainResolver.Strategy != sboption.DomainStrategy(sbc.DomainStrategyIPv4Only) {
			t.Errorf("SendIP %q: resolver strategy %v", test.sendIP, options.DomainResolver.Strategy)
		}
	}
}

func TestLogOptions(t *testing.T) {
	for _, test := range []struct {
		level    string
		disabled bool
		want     string
	}{
		{level: "", disabled: true},
		{level: "none", disabled: true},
		{level: "warning", want: "warn"},
		{level: "Error", want: "error"},
		{level: "debug", want: "debug"},
	} {
		c := &SingBoxController{log: SingBoxLog{Level: test.level, Path: "/var/log/error.log"}}
		options := c.logOptions()
		if options.Disabled != test.disabled || !test.disabled && (options.Level != test.want || options.Output != "/var/log/error.log") {
			t.Errorf("level %q: got %+v", test.level, options)
		}
	}
}

type scriptedPacketConn struct {
	N.PacketConn
	packets []M.Socksaddr
}

func (c *scriptedPacketConn) ReadPacket(buffer *buf.Buffer) (M.Socksaddr, error) {
	if len(c.packets) == 0 {
		return M.Socksaddr{}, io.EOF
	}
	destination := c.packets[0]
	c.packets = c.packets[1:]
	_, _ = buffer.WriteString(destination.String())
	return destination, nil
}

type fakeDNS struct {
	sbadapter.DNSRouter
	answers map[string][]netip.Addr
}

func (d fakeDNS) Lookup(_ context.Context, domain string, _ sbadapter.DNSQueryOptions) ([]netip.Addr, error) {
	if addresses, ok := d.answers[domain]; ok {
		return addresses, nil
	}
	return nil, errors.New("no such domain")
}

func addrs(list ...string) []netip.Addr {
	var addresses []netip.Addr
	for _, addr := range list {
		addresses = append(addresses, netip.MustParseAddr(addr))
	}
	return addresses
}

func TestPublicPacketConnDropsPrivatePackets(t *testing.T) {
	public := M.ParseSocksaddr("1.1.1.1:53")
	domain := M.ParseSocksaddr("example.com:53")
	dns := fakeDNS{answers: map[string][]netip.Addr{
		"example.com": addrs("93.184.215.14"),
		"local.test":  addrs("127.0.0.1"),
		"mixed.test":  addrs("1.1.1.1", "0.0.0.0"),
	}}
	conn := &publicPacketConn{dns: dns, PacketConn: &scriptedPacketConn{packets: []M.Socksaddr{
		M.ParseSocksaddr("127.0.0.1:53"),
		M.ParseSocksaddr("10.0.0.1:53"),
		M.SocksaddrFromNetIP(netip.AddrPortFrom(netip.MustParseAddr("::ffff:192.168.1.1"), 53)),
		M.ParseSocksaddr("[fe80::1]:53"),
		M.ParseSocksaddr("100.100.100.200:80"),
		M.ParseSocksaddr("0.0.0.0:53"),
		M.ParseSocksaddr("[::]:53"),
		M.ParseSocksaddr("local.test:53"),
		M.ParseSocksaddr("mixed.test:53"),
		M.ParseSocksaddr("unknown.test:53"),
		public,
		domain,
	}}}
	for _, want := range []M.Socksaddr{public, domain} {
		buffer := buf.NewSize(64)
		buffer.Resize(8, 0) // headroom the caller reserved
		destination, err := conn.ReadPacket(buffer)
		if err != nil || destination != want {
			t.Fatalf("got %v, %v; want %v", destination, err, want)
		}
		if buffer.Start() != 8 || string(buffer.Bytes()) != want.String() {
			t.Fatalf("buffer starts at %d holding %q, want 8 and %q", buffer.Start(), string(buffer.Bytes()), want.String())
		}
		buffer.Release()
	}
}

func TestGuardRejectsPrivateTargets(t *testing.T) {
	h := &guardOutbound{guard: newSingBoxGuard(log.NewEntry(log.StandardLogger()), nil), blockPrivate: true}
	for _, test := range []struct {
		destination string
		resolved    []netip.Addr
		private     bool
	}{
		{destination: "1.1.1.1:443"},
		{destination: "[2606:4700::1111]:443"},
		{destination: "example.com:443", resolved: addrs("93.184.215.14")},
		{destination: "127.0.0.1:6379", private: true},
		{destination: "0.0.0.0:6379", private: true},
		{destination: "[::]:6379", private: true},
		{destination: "[::1]:6379", private: true},
		{destination: "[::ffff:0.0.0.0]:6379", private: true},
		{destination: "100.100.100.200:80", private: true},
		{destination: "[::%0]:6379", private: true},
		{destination: "[::1%lo]:6379", private: true},
		{destination: "[fe80::1%eth0]:6379", private: true},
		{destination: "[64:ff9b::7f00:1]:6379", private: true},
		{destination: "198.18.0.1:80", private: true},
		{destination: "localhost:6379", resolved: addrs("::1", "127.0.0.1"), private: true},
		{destination: "mixed.test:6379", resolved: addrs("1.1.1.1", "0.0.0.0"), private: true},
		{destination: "unresolved.test:443", private: true},
	} {
		metadata := sbadapter.InboundContext{Destination: M.ParseSocksaddr(test.destination), DestinationAddresses: test.resolved}
		if err := h.checkTarget(&metadata); (err != nil) != test.private {
			t.Errorf("%s (resolved %v): got %v, want private %v", test.destination, test.resolved, err, test.private)
		}
	}
}

// Shadowsocks 2022 keys come from the uuid as Xray derived them for keeper;
// a key two users end up sharing, or one too short, drops them.
func TestValidUsersDerivesShadowsocks2022Keys(t *testing.T) {
	const uuid = "8d9c1c2e-7a4b-4f3e-9b6a-2c1d0e9f8a7b"
	users := []api.UserInfo{
		{UID: 1, UUID: uuid},
		{UID: 2, UUID: "short"},
		{UID: 3, UUID: uuid[:16] + "-differs-later-on"},
	}
	ss := func(method string) *api.NodeInfo {
		return &api.NodeInfo{NodeType: "Shadowsocks", CypherMethod: method}
	}

	valid, secrets, skipped := validUsers(users, nodeSecret(ss("2022-blake3-aes-256-gcm")))
	want := base64.StdEncoding.EncodeToString([]byte(uuid[:32]))
	if len(valid) != 2 || valid[0].UID != 1 || secrets[0] != want {
		t.Fatalf("aes-256: valid %v, secrets %q, want uid 1 keyed %q first", valid, secrets, want)
	}
	if len(skipped) != 1 {
		t.Errorf("aes-256: skipped %q, want the short uuid", skipped)
	}

	// 128-bit keys take the first 16 bytes, which uids 1 and 3 share.
	valid, _, skipped = validUsers(users, nodeSecret(ss("2022-blake3-aes-128-gcm")))
	if len(valid) != 0 || len(skipped) != 2 {
		t.Errorf("aes-128: valid %v, skipped %q, want nobody left", valid, skipped)
	}

	// A legacy AEAD password is the uuid itself.
	_, secrets, _ = validUsers(users[:1], nodeSecret(ss("aes-128-gcm")))
	if secrets[0] != uuid {
		t.Errorf("aes-128-gcm: secret %q, want the uuid", secrets[0])
	}
}
