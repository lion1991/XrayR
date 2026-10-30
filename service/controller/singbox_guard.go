package controller

import (
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"time"

	sbadapter "github.com/sagernet/sing-box/adapter"
	sboutbound "github.com/sagernet/sing-box/adapter/outbound"
	sblog "github.com/sagernet/sing-box/log"
	sboption "github.com/sagernet/sing-box/option"
	sbdirect "github.com/sagernet/sing-box/protocol/direct"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/service"
)

var errUserNotServed = errors.New("user is no longer served by this node")

// singBoxGuard admits connections only for the users the inbound serves now
// and keeps their live connections, so a removed user is cut off at once.
// The inbound alone cannot do that: sessions it authenticated before the
// removal (mux, hysteria2, anytls, snell reuse) keep opening new streams.
// It outlives box rebuilds, like the traffic tracker.
type singBoxGuard struct {
	access  sync.Mutex
	allowed map[string]bool
	conns   map[string]map[*guardedConn]struct{}
}

type guardedConn struct {
	conn io.Closer
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

func newSingBoxGuard() *singBoxGuard {
	return &singBoxGuard{
		allowed: make(map[string]bool),
		conns:   make(map[string]map[*guardedConn]struct{}),
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

// admit registers conn under user, or reports false when user is not
// served. Checking and registering under one lock means admitOnly either
// sees the connection or the connection sees the new list. A connection
// without a user (shared-psk snell) is not tracked.
func (g *singBoxGuard) admit(user string, conn io.Closer) (release func(), ok bool) {
	if user == "" {
		return func() {}, true
	}
	g.access.Lock()
	defer g.access.Unlock()
	if !g.allowed[user] {
		return nil, false
	}
	entry := &guardedConn{conn}
	conns := g.conns[user]
	if conns == nil {
		conns = make(map[*guardedConn]struct{})
		g.conns[user] = conns
	}
	conns[entry] = struct{}{}
	return func() {
		g.access.Lock()
		defer g.access.Unlock()
		delete(conns, entry)
		// conns leaves the registry only once empty, so it is still the
		// user's set here.
		if len(conns) == 0 {
			delete(g.conns, user)
		}
	}, true
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
	release, ok := h.guard.admit(metadata.User, conn)
	if !ok {
		N.CloseOnHandshakeFailure(conn, onClose, errUserNotServed)
		return
	}
	h.connection.NewConnection(ctx, h.Outbound, conn, metadata, releaseOnClose(release, onClose))
}

func (h *guardOutbound) NewPacketConnection(ctx context.Context, conn N.PacketConn, metadata sbadapter.InboundContext, onClose N.CloseHandlerFunc) {
	release, ok := h.guard.admit(metadata.User, conn)
	if !ok {
		N.CloseOnHandshakeFailure(conn, onClose, errUserNotServed)
		return
	}
	h.connection.NewPacketConnection(ctx, h.Outbound, conn, metadata, releaseOnClose(release, onClose))
}

func releaseOnClose(release func(), onClose N.CloseHandlerFunc) N.CloseHandlerFunc {
	return N.OnceClose(func(err error) {
		release()
		if onClose != nil {
			onClose(err)
		}
	})
}
