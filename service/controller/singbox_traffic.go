package controller

import (
	"context"
	"net"
	"sync"
	"sync/atomic"

	sbadapter "github.com/sagernet/sing-box/adapter"
	tun "github.com/sagernet/sing-tun"
	singbufio "github.com/sagernet/sing/common/bufio"
	N "github.com/sagernet/sing/common/network"
	log "github.com/sirupsen/logrus"
)

type userCounter struct {
	up   atomic.Int64
	down atomic.Int64
}

type singBoxTrafficTracker struct {
	access sync.Mutex
	users  map[string]*userCounter
	logger *log.Entry
}

func newSingBoxTrafficTracker(logger *log.Entry) *singBoxTrafficTracker {
	return &singBoxTrafficTracker{
		users:  make(map[string]*userCounter),
		logger: logger,
	}
}

func (t *singBoxTrafficTracker) RoutedConnection(ctx context.Context, conn net.Conn, metadata sbadapter.InboundContext, matchedRule sbadapter.Rule, matchOutbound sbadapter.Outbound) net.Conn {
	user := metadata.User
	if user == "" {
		return conn
	}
	if t.logger != nil {
		outboundTag := ""
		if matchOutbound != nil {
			outboundTag = matchOutbound.Tag()
		}
		t.logger.WithFields(log.Fields{
			"user":     user,
			"source":   metadata.Source.String(),
			"dest":     metadata.Destination.String(),
			"outbound": outboundTag,
		}).Debugf("%s connection", metadata.InboundType)
	}
	counter := t.counter(user)
	return singbufio.NewInt64CounterConn(conn, []*atomic.Int64{&counter.up}, []*atomic.Int64{&counter.down})
}

// RoutedFlow satisfies adapter.ConnectionTracker as of sing-box v1.14. It only
// fires on the TUN pre-match path, where a flow is offloaded instead of being
// routed as a conn — unreachable here, since every inbound we build is a
// listener. Returning nil opts this tracker out of that path; sing-box's own
// trackers do the same when there is nothing to count, and route.go skips nil
// trackers. Accounting stays entirely on Routed{,Packet}Connection below.
func (t *singBoxTrafficTracker) RoutedFlow(ctx context.Context, metadata sbadapter.InboundContext, matchedRule sbadapter.Rule, matchOutbound sbadapter.Outbound) tun.FlowTracker {
	return nil
}

func (t *singBoxTrafficTracker) RoutedPacketConnection(ctx context.Context, conn N.PacketConn, metadata sbadapter.InboundContext, matchedRule sbadapter.Rule, matchOutbound sbadapter.Outbound) N.PacketConn {
	user := metadata.User
	if user == "" {
		return conn
	}
	if t.logger != nil {
		outboundTag := ""
		if matchOutbound != nil {
			outboundTag = matchOutbound.Tag()
		}
		t.logger.WithFields(log.Fields{
			"user":     user,
			"source":   metadata.Source.String(),
			"dest":     metadata.Destination.String(),
			"outbound": outboundTag,
		}).Debugf("%s packet connection", metadata.InboundType)
	}
	counter := t.counter(user)
	return singbufio.NewInt64CounterPacketConn(conn, []*atomic.Int64{&counter.up}, nil, []*atomic.Int64{&counter.down}, nil)
}

func (t *singBoxTrafficTracker) counter(user string) *userCounter {
	t.access.Lock()
	defer t.access.Unlock()
	counter, loaded := t.users[user]
	if !loaded {
		counter = &userCounter{}
		t.users[user] = counter
	}
	return counter
}

// snapshot returns the counter of every user seen so far. Counters are never
// dropped: a removed user's connections can still be open and counting.
func (t *singBoxTrafficTracker) snapshot() map[string]*userCounter {
	t.access.Lock()
	defer t.access.Unlock()
	result := make(map[string]*userCounter, len(t.users))
	for name, counter := range t.users {
		result[name] = counter
	}
	return result
}
