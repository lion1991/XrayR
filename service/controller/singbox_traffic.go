package controller

import (
	"context"
	"net"
	"sync"
	"sync/atomic"

	sbadapter "github.com/sagernet/sing-box/adapter"
	singbufio "github.com/sagernet/sing/common/bufio"
	N "github.com/sagernet/sing/common/network"
	log "github.com/sirupsen/logrus"
)

type singBoxTrafficTracker struct {
	access   sync.Mutex
	counters map[string]*atomic.Int64
	logger   *log.Entry
}

func newSingBoxTrafficTracker(logger *log.Entry) *singBoxTrafficTracker {
	return &singBoxTrafficTracker{
		counters: make(map[string]*atomic.Int64),
		logger:   logger,
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
		}).Info("AnyTLS connection")
	}
	upName := "user>>>" + user + ">>>traffic>>>uplink"
	downName := "user>>>" + user + ">>>traffic>>>downlink"
	t.access.Lock()
	readCounter := t.loadOrCreateCounter(upName)
	writeCounter := t.loadOrCreateCounter(downName)
	t.access.Unlock()
	return singbufio.NewInt64CounterConn(conn, []*atomic.Int64{readCounter}, []*atomic.Int64{writeCounter})
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
		}).Info("AnyTLS packet connection")
	}
	upName := "user>>>" + user + ">>>traffic>>>uplink"
	downName := "user>>>" + user + ">>>traffic>>>downlink"
	t.access.Lock()
	readCounter := t.loadOrCreateCounter(upName)
	writeCounter := t.loadOrCreateCounter(downName)
	t.access.Unlock()
	return singbufio.NewInt64CounterPacketConn(conn, []*atomic.Int64{readCounter}, nil, []*atomic.Int64{writeCounter}, nil)
}

func (t *singBoxTrafficTracker) GetCounter(name string) *atomic.Int64 {
	t.access.Lock()
	counter := t.counters[name]
	t.access.Unlock()
	return counter
}

func (t *singBoxTrafficTracker) loadOrCreateCounter(name string) *atomic.Int64 {
	counter, loaded := t.counters[name]
	if loaded {
		return counter
	}
	counter = &atomic.Int64{}
	t.counters[name] = counter
	return counter
}
