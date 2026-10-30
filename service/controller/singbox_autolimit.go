package controller

import (
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/XrayR-project/XrayR/api"
)

// autoSpeedLimit puts a temporary speed limit on users who keep going faster
// than AutoSpeedLimitConfig allows: over Limit in more than WarnTimes reports
// in a row gets them LimitSpeed for LimitDuration minutes. The guard applies
// the limit; auto limiting never loosens a stricter one from the panel.
type autoSpeedLimit struct {
	config  AutoSpeedLimitConfig
	logger  *log.Entry
	warned  map[int]int       // uid -> reports in a row over the limit
	limited map[int]time.Time // uid -> end of the limit
}

// newAutoSpeedLimit returns nil when auto limiting is off.
func newAutoSpeedLimit(config *AutoSpeedLimitConfig, logger *log.Entry) *autoSpeedLimit {
	if config == nil || config.Limit <= 0 || config.LimitSpeed <= 0 {
		return nil
	}
	return &autoSpeedLimit{
		config:  *config,
		logger:  logger,
		warned:  make(map[int]int),
		limited: make(map[int]time.Time),
	}
}

// observe takes the traffic counted over elapsed and returns the limits now
// in force (bytes per second, per uid); changed says they differ from the
// last call's. The speed is measured over the time actually counted, which
// the report jitter and failed reports stretch past UpdatePeriodic.
func (a *autoSpeedLimit) observe(now time.Time, elapsed time.Duration, traffic []api.UserTraffic) (limits map[int]uint64, changed bool) {
	for uid, end := range a.limited {
		if !now.Before(end) {
			delete(a.limited, uid)
			a.logger.Infof("uid %d: auto speed limit lifted", uid)
			changed = true
		}
	}
	over := make(map[int]bool)
	if seconds := elapsed.Seconds(); seconds > 0 {
		threshold := float64(a.config.Limit) * 1e6 / 8
		for _, user := range traffic {
			if float64(max(user.Upload, user.Download))/seconds > threshold {
				over[user.UID] = true
			}
		}
	}
	for uid := range a.warned {
		if !over[uid] {
			delete(a.warned, uid)
		}
	}
	for uid := range over {
		if _, limited := a.limited[uid]; limited {
			continue
		}
		a.warned[uid]++
		if a.warned[uid] <= a.config.WarnTimes {
			continue
		}
		delete(a.warned, uid)
		end := now.Add(time.Duration(a.config.LimitDuration) * time.Minute)
		a.limited[uid] = end
		a.logger.Infof("uid %d: over %d Mbps, auto limited to %d Mbps until %s",
			uid, a.config.Limit, a.config.LimitSpeed, end.Format("01-02 15:04:05"))
		changed = true
	}
	limits = make(map[int]uint64, len(a.limited))
	for uid := range a.limited {
		limits[uid] = uint64(a.config.LimitSpeed) * 1e6 / 8
	}
	return limits, changed
}
