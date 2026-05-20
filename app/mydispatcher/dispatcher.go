// Package mydispatcher implements the rate limiter and the online device
// counter on top of xray-core's official dispatcher. We register ourselves
// as the routing.Dispatcher feature so xray-core routes every inbound
// connection through our Dispatch / DispatchLink (and from there into
// limiter.GetUserBucket, which populates UserOnlineIP).
package mydispatcher

//go:generate go run github.com/xtls/xray-core/common/errors/errorgen

import "github.com/xtls/xray-core/features/routing"

// Type returns the feature type token. Returning routing.DispatcherType()
// makes this implementation the active dispatcher (replacing the upstream
// app/dispatcher.DefaultDispatcher). For this to work safely, panel.go
// must not also register dispatcher.Config{} — otherwise both register
// the same feature key and the second registration overwrites the first.
func Type() interface{} {
	return routing.DispatcherType()
}
