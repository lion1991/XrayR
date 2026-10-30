package controller

import (
	"context"
	"errors"
	"fmt"
	"io"
	"maps"
	"net"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	sbadapter "github.com/sagernet/sing-box/adapter"
	sboutbound "github.com/sagernet/sing-box/adapter/outbound"
	sblog "github.com/sagernet/sing-box/log"
	sboption "github.com/sagernet/sing-box/option"
	sbdirect "github.com/sagernet/sing-box/protocol/direct"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/common/uot"
	"github.com/sagernet/sing/service"
	log "github.com/sirupsen/logrus"
	"golang.org/x/time/rate"

	"github.com/XrayR-project/XrayR/api"
	"github.com/XrayR-project/XrayR/common/limiter"
)

var (
	errUserNotServed = errors.New("user is no longer served by this node")
	errDeviceLimit   = errors.New("user reached the device limit")
	errAuditRule     = errors.New("destination is rejected by an audit rule")
)

// singBoxGuard decides, before dialing, whether a user's connection may go
// on, and keeps every live one:
//   - Only the users the inbound serves now are admitted, so a removed user is
//     cut off at once. The inbound alone cannot do that: sessions it
//     authenticated before the removal (mux, hysteria2, anytls, snell reuse)
//     keep opening new streams.
//   - A user's devices are the IPs that opened a connection since the last
//     online report, as with Xray; a new IP beyond the device limit is turned
//     away. Live connections do not hold a slot: a phone that moved to another
//     network leaves sockets that look alive for minutes (TCP keepalive) and
//     would lock it out. The report still lists them, so a long-lived
//     connection stays online.
//   - A user with a speed limit gets one token bucket shared by all their
//     connections, both directions.
//   - A destination matching an audit rule is turned away, for every user.
//
// It outlives box rebuilds, like the traffic tracker.
type singBoxGuard struct {
	logger *log.Entry
	global *limiter.GlobalLimiter // nil when the global device limit is off

	access  sync.Mutex
	allowed map[string]bool
	conns   map[string]map[*guardedConn]struct{}
	// Per uid: live connections per IP, and IPs seen since the last report.
	live map[int]map[string]int
	seen map[int]map[string]bool

	nodeSpeedLimit uint64
	policies       map[int]userPolicy
	autoLimits     map[int]uint64 // per uid, bytes per second
	buckets        map[int]*rate.Limiter

	// Its own lock, so a retry storm's logging does not hold up admits.
	logAccess    sync.Mutex
	rejectLogged map[string]time.Time // last time a rejection was logged, per key
	lastPrune    time.Time

	rules atomic.Pointer[[]api.DetectRule]
}

type userPolicy struct {
	speedLimit  uint64 // bytes per second, 0 for none
	deviceLimit int    // 0 for none
}

type guardedConn struct {
	conn    io.Closer
	uid     int
	limited bool // wrapped in the user's bucket
}

// abort ends the connection both ways. Close alone is not enough: a snell
// reuse connection that has replied only half-closes on Close, and the
// client's upload keeps flowing until the destination writes again. An
// expired deadline fails the reads and writes of both copy directions.
func (c *guardedConn) abort() {
	if conn, ok := c.conn.(interface{ SetDeadline(time.Time) error }); ok {
		_ = conn.SetDeadline(time.Unix(1, 0))
	}
	_ = c.conn.Close()
}

func newSingBoxGuard(logger *log.Entry, global *limiter.GlobalLimiter) *singBoxGuard {
	return &singBoxGuard{
		logger:       logger,
		global:       global,
		allowed:      make(map[string]bool),
		conns:        make(map[string]map[*guardedConn]struct{}),
		live:         make(map[int]map[string]int),
		seen:         make(map[int]map[string]bool),
		policies:     make(map[int]userPolicy),
		autoLimits:   make(map[int]uint64),
		buckets:      make(map[int]*rate.Limiter),
		rejectLogged: make(map[string]time.Time),
	}
}

// admitOnly makes names the only users admitted and aborts the connections
// of everyone else.
func (g *singBoxGuard) admitOnly(names ...[]string) {
	allowed := make(map[string]bool)
	for _, list := range names {
		for _, name := range list {
			allowed[name] = true
		}
	}
	var stale []*guardedConn
	g.access.Lock()
	g.allowed = allowed
	for name, conns := range g.conns {
		if allowed[name] {
			continue
		}
		for conn := range conns {
			stale = append(stale, conn)
		}
	}
	g.access.Unlock()
	for _, conn := range stale {
		conn.abort()
	}
}

// setPolicies takes the limits of the panel's users.
func (g *singBoxGuard) setPolicies(nodeSpeedLimit uint64, users []api.UserInfo) {
	policies := make(map[int]userPolicy, len(users))
	for _, user := range users {
		policies[user.UID] = userPolicy{speedLimit: user.SpeedLimit, deviceLimit: user.DeviceLimit}
	}
	g.access.Lock()
	g.nodeSpeedLimit = nodeSpeedLimit
	g.policies = policies
	stale := g.applyRatesLocked()
	g.access.Unlock()
	abortAll(stale)
}

// setAutoLimits replaces the speed limits auto limiting put on users.
func (g *singBoxGuard) setAutoLimits(limits map[int]uint64) {
	g.access.Lock()
	g.autoLimits = maps.Clone(limits)
	stale := g.applyRatesLocked()
	g.access.Unlock()
	abortAll(stale)
}

// applyRatesLocked brings every bucket to its user's current rate, so a
// change applies to the connections open in it. A connection opened while
// its user had no limit is not wrapped and cannot follow; it is returned to
// be aborted once the user gets one, and the client reconnects limited.
func (g *singBoxGuard) applyRatesLocked() (stale []*guardedConn) {
	for uid, bucket := range g.buckets {
		if _, listed := g.policies[uid]; !listed {
			delete(g.buckets, uid)
			continue
		}
		setBucketRate(bucket, g.rateLocked(uid))
	}
	for _, conns := range g.conns {
		for conn := range conns {
			if !conn.limited && g.rateLocked(conn.uid) > 0 {
				stale = append(stale, conn)
			}
		}
	}
	return stale
}

// rateLocked is the user's speed limit in bytes per second, 0 for none: the
// strictest of the node's, the panel's and auto limiting's.
func (g *singBoxGuard) rateLocked(uid int) uint64 {
	return effectiveRate(effectiveRate(g.nodeSpeedLimit, g.policies[uid].speedLimit), g.autoLimits[uid])
}

func abortAll(conns []*guardedConn) {
	for _, conn := range conns {
		conn.abort()
	}
}

// admit registers conn of user from source, or says why it may not go on.
// bucket is non-nil when the user's traffic is to be limited.
func (g *singBoxGuard) admit(user string, source netip.Addr, conn io.Closer) (release func(), bucket *rate.Limiter, err error) {
	// A connection without a user (shared-psk snell) is not tracked.
	if user == "" {
		return func() {}, nil, nil
	}
	uid, email, ok := parseUserTag(user)
	if !ok {
		return nil, nil, errUserNotServed
	}
	ip := source.Unmap().String()

	g.access.Lock()
	err = g.checkLocked(user, uid, ip)
	deviceLimit := g.policies[uid].deviceLimit
	g.access.Unlock()
	if err != nil {
		g.logRejection(uid, deviceLimit, "", err)
		return nil, nil, err
	}
	// The global check talks to Redis, so it runs outside the lock; the
	// local checks run again below, since the user list may change meanwhile.
	if g.global != nil && deviceLimit > 0 &&
		g.global.Reject(limiter.GlobalLimitKey(deviceLimit, email, uid), uid, ip, deviceLimit) {
		g.logRejection(uid, deviceLimit, " across nodes", errDeviceLimit)
		return nil, nil, errDeviceLimit
	}

	// Checking and registering under one lock means admitOnly either sees
	// the connection or the connection sees the new list.
	g.access.Lock()
	defer g.access.Unlock()
	if err := g.checkLocked(user, uid, ip); err != nil {
		g.logRejection(uid, g.policies[uid].deviceLimit, "", err)
		return nil, nil, err
	}
	if limit := g.rateLocked(uid); limit > 0 {
		bucket = g.buckets[uid]
		if bucket == nil {
			bucket = rate.NewLimiter(rate.Limit(limit), int(limit))
			g.buckets[uid] = bucket
		}
	}
	entry := &guardedConn{conn: conn, uid: uid, limited: bucket != nil}
	conns := g.conns[user]
	if conns == nil {
		conns = make(map[*guardedConn]struct{})
		g.conns[user] = conns
	}
	conns[entry] = struct{}{}
	ips := g.live[uid]
	if ips == nil {
		ips = make(map[string]int)
		g.live[uid] = ips
	}
	ips[ip]++
	if g.seen[uid] == nil {
		g.seen[uid] = make(map[string]bool)
	}
	g.seen[uid][ip] = true

	return func() {
		g.access.Lock()
		defer g.access.Unlock()
		delete(conns, entry)
		// A set leaves its map only once empty, so these are still the
		// user's sets here.
		if len(conns) == 0 {
			delete(g.conns, user)
		}
		ips[ip]--
		if ips[ip] == 0 {
			delete(ips, ip)
		}
		if len(ips) == 0 {
			delete(g.live, uid)
		}
	}, bucket, nil
}

func (g *singBoxGuard) checkLocked(user string, uid int, ip string) error {
	if !g.allowed[user] {
		return errUserNotServed
	}
	limit := g.policies[uid].deviceLimit
	if limit <= 0 || g.seen[uid][ip] {
		return nil
	}
	if len(g.seen[uid]) >= limit {
		return errDeviceLimit
	}
	return nil
}

// rejectLogEvery keeps a client retrying against a limit from flooding the
// log: one line per uid and reason in this time.
const rejectLogEvery = time.Minute

func (g *singBoxGuard) logRejection(uid int, deviceLimit int, where string, err error) {
	switch {
	case errors.Is(err, errDeviceLimit):
		if g.shouldLog(fmt.Sprintf("device|%d", uid)) {
			g.logger.Warnf("uid %d reached its device limit (%d)%s (repeats within %v not logged)", uid, deviceLimit, where, rejectLogEvery)
		}
	default:
		// Removed users' clients keep trying until they learn; nothing to act on.
		g.logger.Debugf("uid %d: %v", uid, err)
	}
}

func (g *singBoxGuard) shouldLog(key string) bool {
	g.logAccess.Lock()
	defer g.logAccess.Unlock()
	now := time.Now()
	if last, logged := g.rejectLogged[key]; logged && now.Sub(last) < rejectLogEvery {
		return false
	}
	if now.Sub(g.lastPrune) >= rejectLogEvery {
		for old, last := range g.rejectLogged {
			if now.Sub(last) >= rejectLogEvery {
				delete(g.rejectLogged, old)
			}
		}
		g.lastPrune = now
	}
	g.rejectLogged[key] = now
	return true
}

// onlineUsers lists each user's devices for the online report and starts a
// new period for the device limit.
func (g *singBoxGuard) onlineUsers() []api.OnlineUser {
	g.access.Lock()
	defer g.access.Unlock()
	var online []api.OnlineUser
	for uid, ips := range g.seen {
		for ip := range ips {
			online = append(online, api.OnlineUser{UID: uid, IP: ip})
		}
	}
	for uid, ips := range g.live {
		for ip := range ips {
			if !g.seen[uid][ip] {
				online = append(online, api.OnlineUser{UID: uid, IP: ip})
			}
		}
	}
	g.seen = make(map[int]map[string]bool)
	slices.SortFunc(online, func(a, b api.OnlineUser) int {
		if a.UID != b.UID {
			return a.UID - b.UID
		}
		return strings.Compare(a.IP, b.IP)
	})
	return online
}

func (g *singBoxGuard) setRules(rules []api.DetectRule) {
	g.rules.Store(&rules)
}

// audit returns the first audit rule metadata's destination matches.
func (g *singBoxGuard) audit(metadata *sbadapter.InboundContext) (rule api.DetectRule, target string, hit bool) {
	rules := g.rules.Load()
	if rules == nil || len(*rules) == 0 {
		return api.DetectRule{}, "", false
	}
	for _, target := range auditTargets(metadata) {
		for _, rule := range *rules {
			if rule.Pattern.MatchString(target) {
				return rule, target, true
			}
		}
	}
	return api.DetectRule{}, "", false
}

// auditTargets renders the destination the way Xray does ("tcp:host:port"),
// so the panel's rules keep matching as they did on Xray nodes: the address
// dialed and, if sniffed, the domain. Xray dials the sniffed domain, so one
// string covers both there; sing dials the address, and a client could hide
// it behind an allowed SNI or Host. They are lowercased: Xray lowercases the
// sniffed HTTP host and sing does not, and a rule should not be dodged by
// case anyway.
func auditTargets(metadata *sbadapter.InboundContext) []string {
	destination := metadata.Destination.Unwrap()
	targets := []string{strings.ToLower(metadata.Network + ":" + destination.String())}
	// UDP over TCP leaves its magic name in Domain, not a sniffed one.
	if domain := metadata.Domain; domain != "" && domain != uot.MagicAddress && domain != uot.LegacyMagicAddress {
		sniffed := strings.ToLower(metadata.Network + ":" + M.Socksaddr{Fqdn: domain, Port: destination.Port}.String())
		if sniffed != targets[0] {
			targets = append(targets, sniffed)
		}
	}
	return targets
}

// effectiveRate is the stricter of the node's and the user's limit, either
// of which may be 0 for none.
func effectiveRate(nodeLimit, userLimit uint64) uint64 {
	if nodeLimit == 0 || (userLimit != 0 && userLimit < nodeLimit) {
		return userLimit
	}
	return nodeLimit
}

func setBucketRate(bucket *rate.Limiter, limit uint64) {
	if limit == 0 {
		bucket.SetLimit(rate.Inf)
		return
	}
	bucket.SetLimit(rate.Limit(limit))
	bucket.SetBurst(int(limit))
}

const guardOutboundType = "xrayr-direct"

type guardOutboundOptions struct {
	guard *singBoxGuard
}

func registerGuardOutbound(registry *sboutbound.Registry) {
	sboutbound.Register[guardOutboundOptions](registry, guardOutboundType, newGuardOutbound)
}

// guardOutbound is the node's default outbound: a direct outbound that asks
// the guard before dialing. Embedding the direct outbound keeps every
// interface the router and the connection manager look for on it.
type guardOutbound struct {
	*sbdirect.Outbound
	guard      *singBoxGuard
	connection sbadapter.ConnectionManager
}

func newGuardOutbound(ctx context.Context, router sbadapter.Router, logger sblog.ContextLogger, tag string, options guardOutboundOptions) (sbadapter.Outbound, error) {
	outbound, err := sbdirect.NewOutbound(ctx, router, logger, tag, sboption.DirectOutboundOptions{})
	if err != nil {
		return nil, err
	}
	return &guardOutbound{
		Outbound:   outbound.(*sbdirect.Outbound),
		guard:      options.guard,
		connection: service.FromContext[sbadapter.ConnectionManager](ctx),
	}, nil
}

func (h *guardOutbound) NewConnection(ctx context.Context, conn net.Conn, metadata sbadapter.InboundContext, onClose N.CloseHandlerFunc) {
	if err := h.checkAudit(&metadata); err != nil {
		N.CloseOnHandshakeFailure(conn, onClose, err)
		return
	}
	release, bucket, err := h.guard.admit(metadata.User, metadata.Source.Addr, conn)
	if err != nil {
		N.CloseOnHandshakeFailure(conn, onClose, err)
		return
	}
	if bucket != nil {
		conn = &rateConn{Conn: conn, bucket: bucket}
	}
	h.connection.NewConnection(ctx, h.Outbound, conn, metadata, releaseOnClose(release, onClose))
}

// NewPacketConnection audits the first destination only: a packet connection
// (XUDP, packetaddr) may later send to others.
func (h *guardOutbound) NewPacketConnection(ctx context.Context, conn N.PacketConn, metadata sbadapter.InboundContext, onClose N.CloseHandlerFunc) {
	if err := h.checkAudit(&metadata); err != nil {
		N.CloseOnHandshakeFailure(conn, onClose, err)
		return
	}
	release, bucket, err := h.guard.admit(metadata.User, metadata.Source.Addr, conn)
	if err != nil {
		N.CloseOnHandshakeFailure(conn, onClose, err)
		return
	}
	if bucket != nil {
		conn = &ratePacketConn{PacketConn: conn, bucket: bucket}
	}
	h.connection.NewPacketConnection(ctx, h.Outbound, conn, metadata, releaseOnClose(release, onClose))
}

func (h *guardOutbound) checkAudit(metadata *sbadapter.InboundContext) error {
	rule, target, hit := h.guard.audit(metadata)
	if !hit {
		return nil
	}
	uid, _, _ := parseUserTag(metadata.User) // 0 for a connection without user
	if h.guard.shouldLog(fmt.Sprintf("audit|%d|%d", uid, rule.ID)) {
		h.guard.logger.Warnf("uid %d: access to %s rejected by audit rule %d (repeats within %v not logged)", uid, target, rule.ID, rejectLogEvery)
	}
	return errAuditRule
}

func releaseOnClose(release func(), onClose N.CloseHandlerFunc) N.CloseHandlerFunc {
	return N.OnceClose(func(err error) {
		release()
		if onClose != nil {
			onClose(err)
		}
	})
}
