package limiter

import (
	"context"
	"fmt"
	"time"

	"github.com/eko/gocache/lib/v4/cache"
	"github.com/eko/gocache/lib/v4/marshaler"
	"github.com/eko/gocache/lib/v4/store"
	goCacheStore "github.com/eko/gocache/store/go_cache/v4"
	redisStore "github.com/eko/gocache/store/redis/v4"
	goCache "github.com/patrickmn/go-cache"
	"github.com/redis/go-redis/v9"
	log "github.com/sirupsen/logrus"
)

// GlobalLimiter enforces a user's device limit across nodes by sharing
// their online IPs through Redis. Xray and sing-box nodes build the same key
// (GlobalLimitKey), so both count against one limit.
type GlobalLimiter struct {
	config   *GlobalDeviceLimitConfig
	onlineIP *marshaler.Marshaler
}

// NewGlobalLimiter returns nil when the global limit is off.
func NewGlobalLimiter(config *GlobalDeviceLimitConfig) *GlobalLimiter {
	if config == nil || !config.Enable {
		return nil
	}
	// init local store
	gs := goCacheStore.NewGoCache(goCache.New(time.Duration(config.Expiry)*time.Second, 1*time.Minute))

	// init redis store
	rs := redisStore.NewRedis(redis.NewClient(
		&redis.Options{
			Network:  config.RedisNetwork,
			Addr:     config.RedisAddr,
			Username: config.RedisUsername,
			Password: config.RedisPassword,
			DB:       config.RedisDB,
		}),
		store.WithExpiration(time.Duration(config.Expiry)*time.Second))

	// init chained cache. First use local go-cache, if go-cache is nil, then use redis cache
	cacheManager := cache.NewChain[any](
		cache.New[any](gs), // go-cache is priority
		cache.New[any](rs),
	)
	return &GlobalLimiter{config: config, onlineIP: marshaler.New(cacheManager)}
}

// GlobalLimitKey is the key a user's online IPs are shared under. The Xray
// limiter derives the same string from its user tag.
func GlobalLimitKey(deviceLimit int, email string, uid int) string {
	return fmt.Sprintf("%d|%s|%d", deviceLimit, email, uid)
}

// Reject reports whether the user under key is already over deviceLimit on
// all nodes together, and records ip for them otherwise.
func (g *GlobalLimiter) Reject(key string, uid int, ip string, deviceLimit int) bool {
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(g.config.Timeout)*time.Second)
	defer cancel()

	v, err := g.onlineIP.Get(ctx, key, new(map[string]int))
	if err != nil {
		if _, ok := err.(*store.NotFound); ok {
			// If the email is a new device
			go g.pushIP(key, &map[string]int{ip: uid})
		} else {
			log.Errorf("global device limit cache: %v", err)
		}
		return false
	}

	ipMap := v.(*map[string]int)
	reject, added := addDevice(*ipMap, ip, uid, deviceLimit)
	if added {
		go g.pushIP(key, ipMap)
	}
	return reject
}

// addDevice adds ip to the user's devices unless that goes over limit. A
// known ip always passes, so a user at the limit keeps their devices.
func addDevice(ipMap map[string]int, ip string, uid int, limit int) (reject bool, added bool) {
	if _, ok := ipMap[ip]; ok {
		return false, false
	}
	if limit > 0 && len(ipMap) >= limit {
		return true, false
	}
	ipMap[ip] = uid
	return false, true
}

// push the ip to cache
func (g *GlobalLimiter) pushIP(key string, ipMap *map[string]int) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(g.config.Timeout)*time.Second)
	defer cancel()

	if err := g.onlineIP.Set(ctx, key, ipMap); err != nil {
		log.Errorf("global device limit cache: %v", err)
	}
}
