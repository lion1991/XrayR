package controller

import (
	"math/rand/v2"
	"sync/atomic"
	"time"

	"github.com/XrayR-project/XrayR/api"
)

// jitterHolder carries the current max heartbeat jitter. It is refreshed each
// pull cycle from the panel's base_config (node-local config as fallback) and
// read on every task run by withJitter, so a panel change takes effect within
// one pull without restarting the node. Safe for concurrent read/write.
type jitterHolder struct{ ns atomic.Int64 }

func (h *jitterHolder) set(d time.Duration) { h.ns.Store(int64(d)) }
func (h *jitterHolder) get() time.Duration  { return time.Duration(h.ns.Load()) }

// withJitter wraps a periodic task's Execute so each invocation is preceded by
// a random delay in [0, current jitter). xray-core's task.Periodic schedules
// the next run a fixed Interval after Execute returns, so folding the delay in
// turns a fixed-period node<->panel beacon into an irregular cadence in
// [Interval, Interval+jitter) — desynchronising the poll/report heartbeat
// without touching the task framework. The delay is read live each cycle, so
// pull and push draw independently and a panel change is picked up within one
// pull. jitter <= 0 runs fn immediately (behaviour identical to stock XrayR).
func withJitter(h *jitterHolder, fn func() error) func() error {
	return func() error {
		if d := h.get(); d > 0 {
			time.Sleep(time.Duration(rand.Int64N(int64(d))))
		}
		return fn()
	}
}

// jitterProvider is implemented by API clients that surface the panel's
// base_config.interval_jitter (currently newV2board). Clients that don't are
// treated as "no panel jitter" and the node-local value is used.
type jitterProvider interface {
	GetIntervalJitter() int
}

// effectiveJitter resolves the heartbeat jitter to apply: the panel value when
// set (>0), else the node-local UpdatePeriodicJitter, as a Duration (0 = off).
func effectiveJitter(apiClient api.API, localSec int) time.Duration {
	panelSec := 0
	if jp, ok := apiClient.(jitterProvider); ok {
		panelSec = jp.GetIntervalJitter()
	}
	return resolveJitter(panelSec, localSec)
}

// resolveJitter applies the panel-over-local precedence: the panel value wins
// when set (>0), otherwise the node-local value; <=0 either way means disabled.
func resolveJitter(panelSec, localSec int) time.Duration {
	sec := panelSec
	if sec <= 0 {
		sec = localSec
	}
	if sec <= 0 {
		return 0
	}
	return time.Duration(sec) * time.Second
}
