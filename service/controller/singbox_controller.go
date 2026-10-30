package controller

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"net/netip"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	sb "github.com/sagernet/sing-box"
	sbadapter "github.com/sagernet/sing-box/adapter"
	sbcertificate "github.com/sagernet/sing-box/adapter/certificate"
	sbendpoint "github.com/sagernet/sing-box/adapter/endpoint"
	sbinbound "github.com/sagernet/sing-box/adapter/inbound"
	sboutbound "github.com/sagernet/sing-box/adapter/outbound"
	sbservice "github.com/sagernet/sing-box/adapter/service"
	sbc "github.com/sagernet/sing-box/constant"
	sbdns "github.com/sagernet/sing-box/dns"
	sblocaldns "github.com/sagernet/sing-box/dns/transport/local"
	sboption "github.com/sagernet/sing-box/option"
	sbanytls "github.com/sagernet/sing-box/protocol/anytls"
	sbhysteria "github.com/sagernet/sing-box/protocol/hysteria"
	sbhysteria2 "github.com/sagernet/sing-box/protocol/hysteria2"
	sbsnell "github.com/sagernet/sing-box/protocol/snell"
	"github.com/sagernet/sing/common/json/badoption"
	N "github.com/sagernet/sing/common/network"
	log "github.com/sirupsen/logrus"
	"github.com/xtls/xray-core/common/task"

	"github.com/XrayR-project/XrayR/api"
	"github.com/XrayR-project/XrayR/common/limiter"
)

type SingBoxController struct {
	config     *Config
	clientInfo api.ClientInfo
	apiClient  api.API

	tasks     []periodicTask
	jitter    jitterHolder
	panelType string

	startAt time.Time
	logger  *log.Entry
	log     SingBoxLog
	// allowPrivate lets connections reach private addresses, for tests that
	// dial local servers.
	allowPrivate bool

	// Outlives box rebuilds, so traffic counted before a rebuild still gets
	// reported after it.
	traffic *singBoxTrafficTracker
	guard   *singBoxGuard
	// Only the traffic monitor touches these.
	autoLimit    *autoSpeedLimit // nil when auto limiting is off
	trafficSince time.Time       // start of the traffic not yet reported

	// access guards everything below; the node monitor, the traffic monitor
	// and Close run on different goroutines.
	access sync.Mutex
	// What the panel last sent.
	nodeInfo *api.NodeInfo
	userList *[]api.UserInfo
	// What the running box was built from. box is nil while the node has no
	// usable user, or after a rebuild failed to start.
	box      *sb.Box
	boxNode  *api.NodeInfo
	boxUsers map[string]string // user name -> secret
	// credentials gives each uid's secret a version that goes into the
	// user's name, so a changed secret is a new name: sessions authenticated
	// with the old secret keep the old name, which the guard stops admitting.
	credentials map[int]credential
	// Tag is the running box's inbound tag.
	Tag string
	// boxGeneration counts box builds, so tests can tell a rebuild apart.
	boxGeneration int
	// closed stops a poll that was already in flight when Close ran from
	// bringing a box back up.
	closed bool
	// lastWarnings holds the user problems last logged, so a poll repeats
	// them only when they change.
	lastWarnings []string
}

// SingBoxLog is the panel's Log config as sing-box reads it.
type SingBoxLog struct {
	Level string // none, error, warning, info or debug
	Path  string // empty logs to stderr
}

func NewSingBoxController(apiClient api.API, config *Config, panelType string, logConfig SingBoxLog) *SingBoxController {
	logger := log.NewEntry(log.StandardLogger()).WithFields(log.Fields{
		"Host": apiClient.Describe().APIHost,
		"Type": apiClient.Describe().NodeType,
		"ID":   apiClient.Describe().NodeID,
	})
	return &SingBoxController{
		config:    config,
		apiClient: apiClient,
		panelType: panelType,
		startAt:   time.Now(),
		logger:    logger,
		log:       logConfig,
	}
}

func (c *SingBoxController) Start() error {
	c.clientInfo = c.apiClient.Describe()

	newNodeInfo, err := c.apiClient.GetNodeInfo()
	if err != nil {
		return err
	}
	if newNodeInfo.Port == 0 {
		return errors.New("server port must > 0")
	}
	userInfo, err := getUserList(c.apiClient)
	if err != nil {
		return err
	}
	c.traffic = newSingBoxTrafficTracker(c.logger)
	c.guard = newSingBoxGuard(c.logger, limiter.NewGlobalLimiter(c.config.GlobalDeviceLimitConfig))
	c.credentials = make(map[int]credential)
	c.autoLimit = newAutoSpeedLimit(c.config.AutoSpeedLimitConfig, c.logger)
	c.trafficSince = time.Now()
	c.pullRules()

	c.access.Lock()
	c.nodeInfo = newNodeInfo
	c.userList = userInfo
	err = c.sync()
	c.access.Unlock()
	if err != nil {
		return err
	}

	interval := time.Duration(c.config.UpdatePeriodic) * time.Second
	if interval <= 0 {
		interval = 60 * time.Second
	}

	// Fold a random delay into each poll/report so the node<->panel cadence
	// isn't a fixed-period beacon (see withJitter). Refreshed from the panel
	// on every node info pull.
	c.jitter.set(effectiveJitter(c.apiClient, c.config.UpdatePeriodicJitter))
	c.tasks = append(c.tasks, periodicTask{
		tag: "node monitor",
		Periodic: &task.Periodic{
			Interval: interval,
			Execute:  withJitter(&c.jitter, c.nodeInfoMonitor),
		},
	})
	c.tasks = append(c.tasks, periodicTask{
		tag: "traffic monitor",
		Periodic: &task.Periodic{
			Interval: interval,
			Execute:  withJitter(&c.jitter, c.trafficMonitor),
		},
	})

	for i := range c.tasks {
		c.logger.Printf("Start %s periodic task", c.tasks[i].tag)
		go c.tasks[i].Start()
	}

	return nil
}

// nodeInfoMonitor pulls node info and users from the panel and brings the box
// in line with them. It also serves as the panel heartbeat. It never returns
// an error, since that would stop the periodic task for good.
func (c *SingBoxController) nodeInfoMonitor() error {
	if time.Since(c.startAt) < time.Duration(c.config.UpdatePeriodic)*time.Second {
		return nil
	}
	// keeper answers 304 against an ETag that each successful pull advances,
	// so whatever a pull returns must be kept even if the other pull fails:
	// the next one would only say "not modified".
	newNodeInfo, err := c.apiClient.GetNodeInfo()
	if err != nil {
		if err.Error() != api.NodeNotModified {
			c.logger.Print(err)
		}
		newNodeInfo = nil
	} else if newNodeInfo.Port == 0 {
		c.logger.Print("server port must > 0")
		newNodeInfo = nil
	}
	// keeper derives the rules from the node info it just pulled.
	c.pullRules()
	newUserInfo, err := getUserList(c.apiClient)
	if err != nil {
		if err.Error() != api.UserNotModified {
			c.logger.Print(err)
		}
		newUserInfo = nil
	}
	c.jitter.set(effectiveJitter(c.apiClient, c.config.UpdatePeriodicJitter))

	c.access.Lock()
	defer c.access.Unlock()
	if c.closed {
		return nil
	}
	if newNodeInfo != nil {
		c.nodeInfo = newNodeInfo
	}
	if newUserInfo != nil {
		c.userList = newUserInfo
	}
	if err := c.sync(); err != nil {
		c.logger.Print(err)
	}
	return nil
}

// pullRules hands the panel's audit rules to the guard. An empty list clears
// them, so rules removed on the panel stop applying.
func (c *SingBoxController) pullRules() {
	if c.config.DisableGetRule {
		return
	}
	rules, err := c.apiClient.GetNodeRule()
	if err != nil {
		if err.Error() != api.RuleNotModified {
			c.logger.Printf("Get rule list failed: %s", err)
		}
		return
	}
	c.guard.setRules(*rules)
}

func (c *SingBoxController) Close() error {
	for i := range c.tasks {
		if c.tasks[i].Periodic != nil {
			if err := c.tasks[i].Periodic.Close(); err != nil {
				c.logger.Panicf("%s periodic task close failed: %s", c.tasks[i].tag, err)
			}
		}
	}
	c.tasks = nil
	c.access.Lock()
	c.closed = true
	c.closeBox()
	c.access.Unlock()
	return nil
}

// sync rebuilds the box when the node info changed (or no box is running),
// otherwise replaces the inbound's users in place if they changed. A failed
// sync leaves the desired state in place, so the next poll retries it.
func (c *SingBoxController) sync() error {
	nodeInfo := c.nodeInfo
	users, secrets, warnings := validUsers(*c.userList)
	c.trackCredentials(users, secrets)
	// Limits change without touching the inbound.
	c.guard.setPolicies(nodeInfo.SpeedLimit, users)
	needUsers := nodeNeedsUsers(nodeInfo)
	if needUsers && len(users) == 0 {
		// An inbound with no users is never what the panel means: snell
		// would fall back to its shared psk and admit anyone holding it, and
		// the rest would admit nobody. Serve nothing until a user shows up.
		if c.box != nil {
			c.logger.Warn("no usable user left, stopping the inbound until one shows up")
			c.closeBox()
		}
		warnings = append(warnings, "no usable user, the inbound starts once one shows up")
	}
	if !slices.Equal(warnings, c.lastWarnings) {
		for _, warning := range warnings {
			c.logger.Warn(warning)
		}
		c.lastWarnings = warnings
	}
	if needUsers && len(users) == 0 {
		return nil
	}
	if c.box == nil || !reflect.DeepEqual(c.boxNode, nodeInfo) {
		err := c.rebuild(nodeInfo, users, secrets)
		if err == nil || c.box == nil {
			return err
		}
		// The new node info was rejected and the old box keeps serving; its
		// users must still follow the panel until the node info is fixed.
		c.logger.Print(err)
		nodeInfo = c.boxNode
		needUsers = nodeNeedsUsers(nodeInfo)
	}
	if !needUsers {
		return nil
	}
	tag := c.Tag
	names := c.userNames(tag, users)
	wanted := userSecretMap(names, secrets)
	if maps.Equal(wanted, c.boxUsers) {
		return nil
	}
	// Admit the new names before the inbound starts authenticating them, so
	// their first connection is not turned away.
	c.guard.admitOnly(slices.Collect(maps.Keys(c.boxUsers)), names)
	err := c.updateInboundUsers(nodeInfo, tag, names, secrets)
	if errors.Is(err, errUsersNotReplaceable) {
		return c.rebuild(nodeInfo, users, secrets)
	}
	if err != nil {
		return err
	}
	// The inbound no longer authenticates the removed users; now cut off
	// what they still have open.
	c.guard.admitOnly(names)
	added, removed := diffUsers(c.boxUsers, wanted)
	c.logger.Printf("%d user added, %d user deleted", added, removed)
	c.boxUsers = wanted
	return nil
}

// rebuild builds the new box before stopping the old one, so a node info
// sing-box rejects leaves the old box serving. Failing to start the new box
// (say, its port is taken) leaves no box; the next poll tries again.
func (c *SingBoxController) rebuild(nodeInfo *api.NodeInfo, users []api.UserInfo, secrets []string) error {
	tag := buildNodeTag(nodeInfo, c.config.ListenIP)
	names := c.userNames(tag, users)
	newBox, err := c.newBox(nodeInfo, tag, names, secrets)
	if err != nil {
		return err
	}
	c.closeBox()
	c.guard.admitOnly(names)
	if err := newBox.Start(); err != nil {
		_ = newBox.Close()
		return err
	}
	c.box = newBox
	c.boxNode = nodeInfo
	c.boxUsers = userSecretMap(names, secrets)
	c.Tag = tag
	c.boxGeneration++
	c.logger.Printf("sing-box node started with %d user(s)", len(users))
	return nil
}

func (c *SingBoxController) closeBox() {
	if c.box != nil {
		_ = c.box.Close()
	}
	c.box = nil
	c.boxNode = nil
	c.boxUsers = nil
}

var errUsersNotReplaceable = errors.New("inbound cannot replace users at runtime")

func (c *SingBoxController) updateInboundUsers(nodeInfo *api.NodeInfo, tag string, names, secrets []string) error {
	inbound, loaded := c.box.Inbound().Get(tag)
	if !loaded {
		return fmt.Errorf("inbound %s not found", tag)
	}
	switch strings.ToLower(nodeInfo.NodeType) {
	case "anytls":
		return replaceUsers(inbound, inboundUsers(names, secrets, anytlsUser))
	case "hysteria":
		if nodeInfo.HysteriaVersion == 2 {
			return replaceUsers(inbound, inboundUsers(names, secrets, hysteria2User))
		}
		return errUsersNotReplaceable
	case "snell":
		return replaceUsers(inbound, inboundUsers(names, secrets, snellUser))
	}
	return errUsersNotReplaceable
}

func replaceUsers[U any](inbound sbadapter.Inbound, users []U) error {
	managed, ok := inbound.(sbadapter.ManagedUserInbound[U])
	if !ok {
		return errUsersNotReplaceable
	}
	return managed.UpdateUsers(users)
}

// nodeNeedsUsers is false for a shared-psk snell node, which ignores users.
func nodeNeedsUsers(nodeInfo *api.NodeInfo) bool {
	return !strings.EqualFold(nodeInfo.NodeType, "snell") || nodeInfo.SnellMultiUser
}

// getUserList treats keeper's "users is null" as the empty list it is: the
// pull already advanced the ETag, so keeping the old list would keep the last
// removed users admitted for good.
func getUserList(apiClient api.API) (*[]api.UserInfo, error) {
	users, err := apiClient.GetUserList()
	if err != nil && err.Error() == api.UserListEmpty {
		return &[]api.UserInfo{}, nil
	}
	return users, err
}

func buildNodeTag(nodeInfo *api.NodeInfo, listenIP string) string {
	return fmt.Sprintf("%s_%s_%d", nodeInfo.NodeType, listenIP, nodeInfo.Port)
}

type credential struct {
	secret  string
	version int
}

// trackCredentials bumps the version of every uid whose secret changed.
// Versions are kept for removed uids too, so a uid coming back with another
// secret does not reuse a name an old session may still hold.
func (c *SingBoxController) trackCredentials(users []api.UserInfo, secrets []string) {
	for i, user := range users {
		known, loaded := c.credentials[user.UID]
		if !loaded {
			c.credentials[user.UID] = credential{secret: secrets[i]}
		} else if known.secret != secrets[i] {
			c.credentials[user.UID] = credential{secret: secrets[i], version: known.version + 1}
		}
	}
}

func (c *SingBoxController) userNames(nodeTag string, users []api.UserInfo) []string {
	names := make([]string, len(users))
	for i := range users {
		names[i] = userTag(nodeTag, &users[i], c.credentials[users[i].UID].version)
	}
	return names
}

// userTag is the user's name inside sing-box, which is what traffic is
// counted under and what the guard admits. parseUserTag reverses it.
func userTag(nodeTag string, user *api.UserInfo, version int) string {
	return fmt.Sprintf("%s|%s|%d|%d", nodeTag, user.Email, user.UID, version)
}

func parseUserTag(name string) (uid int, email string, ok bool) {
	index := strings.LastIndexByte(name, '|')
	if index < 0 {
		return 0, "", false
	}
	name = name[:index]
	index = strings.LastIndexByte(name, '|')
	if index < 0 {
		return 0, "", false
	}
	uid, err := strconv.Atoi(name[index+1:])
	if err != nil {
		return 0, "", false
	}
	_, email, ok = strings.Cut(name[:index], "|")
	return uid, email, ok
}

func userSecretMap(names, secrets []string) map[string]string {
	result := make(map[string]string, len(names))
	for i, name := range names {
		result[name] = secrets[i]
	}
	return result
}

func diffUsers(old, new map[string]string) (added, removed int) {
	for name := range new {
		if _, loaded := old[name]; !loaded {
			added++
		}
	}
	for name := range old {
		if _, loaded := new[name]; !loaded {
			removed++
		}
	}
	return added, removed
}

// validUsers drops the users the inbound cannot serve correctly and says why.
// Dropping them keeps one bad entry from failing the whole update, which
// replaces all users or none.
//   - The secret is the password, falling back to the UUID; without one the
//     user cannot authenticate.
//   - A UID listed twice would give two users the same name.
//   - Users sharing a secret are indistinguishable to the inbound, so one
//     would be billed for the other; all of them are dropped. sing-anytls and
//     sing-quic would silently keep the last one.
func validUsers(users []api.UserInfo) (valid []api.UserInfo, secrets []string, skipped []string) {
	seenUIDs := make(map[int]bool, len(users))
	owners := make(map[string][]int, len(users))
	candidates := make([]api.UserInfo, 0, len(users))
	for _, user := range users {
		if seenUIDs[user.UID] {
			skipped = append(skipped, fmt.Sprintf("skip user: uid %d is listed more than once", user.UID))
			continue
		}
		seenUIDs[user.UID] = true
		secret := userSecret(&user)
		if secret == "" {
			skipped = append(skipped, fmt.Sprintf("skip user: uid %d has empty password/uuid", user.UID))
			continue
		}
		owners[secret] = append(owners[secret], user.UID)
		candidates = append(candidates, user)
	}
	for _, user := range candidates {
		secret := userSecret(&user)
		if uids := owners[secret]; len(uids) > 1 {
			if uids[0] == user.UID {
				skipped = append(skipped, fmt.Sprintf("skip users: uids %v share the same password/uuid", uids))
			}
			continue
		}
		valid = append(valid, user)
		secrets = append(secrets, secret)
	}
	return valid, secrets, skipped
}

func userSecret(user *api.UserInfo) string {
	if user.Passwd != "" {
		return user.Passwd
	}
	return user.UUID
}

func inboundUsers[U any](names, secrets []string, build func(name, secret string) U) []U {
	result := make([]U, len(names))
	for i, name := range names {
		result[i] = build(name, secrets[i])
	}
	return result
}

func anytlsUser(name, secret string) sboption.AnyTLSUser {
	return sboption.AnyTLSUser{Name: name, Password: secret}
}

func hysteria2User(name, secret string) sboption.Hysteria2User {
	return sboption.Hysteria2User{Name: name, Password: secret}
}

func hysteriaUser(name, secret string) sboption.HysteriaUser {
	return sboption.HysteriaUser{Name: name, AuthString: secret}
}

func snellUser(name, secret string) sboption.SnellUser {
	return sboption.SnellUser{Name: name, UserKey: secret}
}

// newBox builds a box for the node without starting it, so nothing listens
// yet.
func (c *SingBoxController) newBox(nodeInfo *api.NodeInfo, tag string, names, secrets []string) (*sb.Box, error) {
	nodeType := strings.ToLower(nodeInfo.NodeType)
	switch nodeType {
	case "anytls", "hysteria", "snell":
	default:
		return nil, fmt.Errorf("unsupported node type for sing-box controller: %s", nodeInfo.NodeType)
	}
	if nodeInfo.Port > 65535 {
		return nil, fmt.Errorf("invalid listen port: %d", nodeInfo.Port)
	}

	var listenAddr netip.Addr
	if c.config.ListenIP != "" {
		addr, err := netip.ParseAddr(c.config.ListenIP)
		if err != nil {
			return nil, fmt.Errorf("invalid listen ip %q: %w", c.config.ListenIP, err)
		}
		listenAddr = addr
	} else {
		listenAddr = netip.IPv4Unspecified()
	}
	listenBadAddr := badoption.Addr(listenAddr)
	lo := sboption.ListenOptions{
		Listen:     &listenBadAddr,
		ListenPort: uint16(nodeInfo.Port),
	}

	var tlsOptions *sboption.InboundTLSOptions
	if nodeInfo.EnableTLS {
		if c.config.CertConfig == nil || c.config.CertConfig.CertMode == "none" {
			return nil, fmt.Errorf("tls is required but CertConfig is not configured")
		}
		certFile, keyFile, err := getCertFile(c.config.CertConfig)
		if err != nil {
			return nil, err
		}
		tlsOptions = &sboption.InboundTLSOptions{
			Enabled:         true,
			CertificatePath: certFile,
			KeyPath:         keyFile,
		}
	}

	inReg := sbinbound.NewRegistry()
	var inboundType string
	var inboundOptions any

	switch nodeType {
	case "anytls":
		sbanytls.RegisterInbound(inReg)
		anytlsOptions := &sboption.AnyTLSInboundOptions{
			ListenOptions: lo,
			InboundTLSOptionsContainer: sboption.InboundTLSOptionsContainer{
				TLS: tlsOptions,
			},
			Users: inboundUsers(names, secrets, anytlsUser),
		}
		if len(nodeInfo.PaddingScheme) > 0 {
			anytlsOptions.PaddingScheme = badoption.Listable[string](nodeInfo.PaddingScheme)
		}
		inboundType = sbc.TypeAnyTLS
		inboundOptions = anytlsOptions
	case "hysteria":
		// choose hy1 or hy2 by version, default hy2 when version==2
		version := nodeInfo.HysteriaVersion
		if version == 2 {
			sbhysteria2.RegisterInbound(inReg)
			var obfs *sboption.Hysteria2Obfs
			if nodeInfo.HysteriaObfs != "" {
				obfs = &sboption.Hysteria2Obfs{
					Type:     nodeInfo.HysteriaObfs,
					Password: nodeInfo.HysteriaObfsPassword,
				}
			}
			h2Options := &sboption.Hysteria2InboundOptions{
				ListenOptions: lo,
				InboundTLSOptionsContainer: sboption.InboundTLSOptionsContainer{
					TLS: tlsOptions,
				},
				UpMbps:   nodeInfo.HysteriaUpMbps,
				DownMbps: nodeInfo.HysteriaDownMbps,
				Obfs:     obfs,
				Users:    inboundUsers(names, secrets, hysteria2User),
			}
			inboundType = sbc.TypeHysteria2
			inboundOptions = h2Options
		} else {
			sbhysteria.RegisterInbound(inReg)
			hOptions := &sboption.HysteriaInboundOptions{
				ListenOptions: lo,
				InboundTLSOptionsContainer: sboption.InboundTLSOptionsContainer{
					TLS: tlsOptions,
				},
				UpMbps:   nodeInfo.HysteriaUpMbps,
				DownMbps: nodeInfo.HysteriaDownMbps,
				Obfs:     nodeInfo.HysteriaObfs,
				Users:    inboundUsers(names, secrets, hysteriaUser),
			}
			inboundType = sbc.TypeHysteria
			inboundOptions = hOptions
		}
	case "snell":
		sbsnell.RegisterInbound(inReg)
		version := nodeInfo.SnellVersion
		// sing-box serves v5 and v6 only — its v4 support is client-side.
		// Reject here rather than let sing-snell fail deeper in with an error
		// the operator can't trace back to a panel field.
		if version != 5 && version != 6 {
			return nil, fmt.Errorf("snell: unsupported version %d (sing-box serves 5 or 6)", version)
		}
		psk := nodeInfo.SnellPSK
		if psk == "" {
			return nil, errors.New("snell: psk is required but the panel sent none")
		}
		// Mirrors snell-server v6's own check, which sing-snell reproduces.
		if version == 6 && (len(psk) < 12 || len(psk) > 255) {
			return nil, fmt.Errorf("snell: v6 psk must be 12-255 bytes, panel sent %d", len(psk))
		}

		snellOptions := &sboption.SnellInboundOptions{
			Version: version,
			AbstractSnellInboundOptions: sboption.AbstractSnellInboundOptions{
				ListenOptions: lo,
				PSK:           psk,
			},
		}
		if version == 6 {
			snellOptions.V6Options = sboption.SnellV6Options{Mode: nodeInfo.SnellMode}
		} else {
			snellOptions.ObfsOptions = sboption.SnellObfsServerOptions{ObfsMode: nodeInfo.SnellObfs}
		}

		// The two user models are mutually exclusive, and the choice is the
		// panel's (multi_user in protocol_settings):
		//
		//   multi_user=false — one shared psk. Any client holding it connects,
		//     including official Surge. Nobody is identified, so metadata.User
		//     is blank, the traffic tracker attributes nothing, and this node
		//     reports zero usage to the panel. Unmetered by construction.
		//
		//   multi_user=true — each user's uuid is their Snell key, which rides
		//     in the request's ClientID field. That gives us per-user traffic
		//     and lets sing-snell reject unknown keys. But Surge has no config
		//     option for a client id: it sends an empty one and sing-snell
		//     turns that into ErrBadUserKey, so official Surge clients cannot
		//     connect to a node in this mode. Only sing-box-family clients can.
		if nodeInfo.SnellMultiUser {
			// v5 + multi_user is a node no client can reach, so refuse to boot
			// one rather than let it sit there looking healthy: official Surge
			// speaks v5 but cannot send a client-id, and the only clients that
			// can send one are sing-box-family — which implement no v5 client
			// at all (sing-snell ships snellv5/server.go with no client.go).
			if version == 5 {
				return nil, errors.New("snell: version 5 with multi_user has no reachable client — Surge cannot send a client-id and sing-box has no v5 client. Use version 6, or turn multi_user off")
			}
			// sing-box picks the service implementation off len(Users): an
			// empty list builds the SHARED-PSK service, not a multi-user one
			// that admits nobody. sync never builds a box without users; pin
			// it here too, since getting it wrong admits any psk holder
			// unmetered.
			if len(names) == 0 {
				return nil, errors.New("snell: multi_user is on but there are zero users — refusing to build: sing-box would fall back to shared-psk mode and admit any psk holder unmetered")
			}
			snellOptions.Users = inboundUsers(names, secrets, snellUser)
		} else {
			c.logger.Warn("snell: shared-psk mode — all users share the node psk, so no traffic can be attributed and this node will report zero usage to the panel. Set multi_user on the node to meter users (note: official Surge clients cannot connect in that mode).")
		}

		inboundType = sbc.TypeSnell
		inboundOptions = snellOptions
	}

	strategy, err := domainStrategy(c.config)
	if err != nil {
		return nil, err
	}
	direct, err := c.directOptions(strategy)
	if err != nil {
		return nil, err
	}

	outReg := sboutbound.NewRegistry()
	registerGuardOutbound(outReg)

	ctx := context.Background()
	// sing-box's box.New unconditionally configures a default DNS fallback
	// of type "local"; the registry must contain that transport or startup
	// panics with "transport type not found: local". The local transport
	// only registers on demand, so we wire it explicitly here.
	dnsTransportReg := sbdns.NewTransportRegistry()
	sblocaldns.RegisterTransport(dnsTransportReg)
	ctx = sb.Context(
		ctx,
		inReg,
		outReg,
		sbendpoint.NewRegistry(),
		dnsTransportReg,
		sbservice.NewRegistry(),
		// sing-box v1.14 added a certificate-provider registry to the context.
		// We issue no certificates from providers (CertConfig hands us files on
		// disk), but box.New dereferences the registry, so it must be present.
		sbcertificate.NewRegistry(),
	)

	options := sb.Options{
		Options: sboption.Options{
			Log: c.logOptions(),
			DNS: &sboption.DNSOptions{RawDNSOptions: sboption.RawDNSOptions{
				Servers: []sboption.DNSServerOptions{{
					Type:    sbc.DNSTypeLocal,
					Tag:     dnsServerTag,
					Options: &sboption.LocalDNSServerOptions{},
				}},
			}},
			Inbounds: []sboption.Inbound{
				{
					Type:    inboundType,
					Tag:     tag,
					Options: inboundOptions,
				},
			},
			// The first outbound is the default one, which every connection
			// takes.
			Outbounds: []sboption.Outbound{
				{
					Type:    guardOutboundType,
					Tag:     "direct",
					Options: &guardOutboundOptions{guard: c.guard, direct: direct, blockPrivate: !c.allowPrivate},
				},
			},
			Route: c.routeOptions(strategy),
		},
		Context: ctx,
	}

	boxInstance, err := sb.New(options)
	if err != nil {
		return nil, err
	}
	boxInstance.Router().AppendTracker(c.traffic)
	return boxInstance, nil
}

const dnsServerTag = "local"

// logOptions maps the panel's log level; the Xray-only access log has no
// counterpart.
func (c *SingBoxController) logOptions() *sboption.LogOptions {
	level := strings.ToLower(c.log.Level)
	switch level {
	case "", "none":
		return &sboption.LogOptions{Disabled: true}
	case "warning":
		level = "warn"
	}
	return &sboption.LogOptions{Level: level, Output: c.log.Path, Timestamp: true, DisableColor: true}
}

// domainStrategy reads DNSType as the Xray freedom outbound does: without
// EnableDNS, domains resolve in both families.
func domainStrategy(config *Config) (sboption.DomainStrategy, error) {
	if !config.EnableDNS {
		return sboption.DomainStrategy(sbc.DomainStrategyAsIS), nil
	}
	switch strings.ToLower(config.DNSType) {
	case "", "asis", "useip", "forceip":
		return sboption.DomainStrategy(sbc.DomainStrategyAsIS), nil
	case "useipv4", "forceipv4":
		return sboption.DomainStrategy(sbc.DomainStrategyIPv4Only), nil
	case "useipv6", "forceipv6":
		return sboption.DomainStrategy(sbc.DomainStrategyIPv6Only), nil
	case "useipv4v6", "forceipv4v6":
		return sboption.DomainStrategy(sbc.DomainStrategyPreferIPv4), nil
	case "useipv6v4", "forceipv6v4":
		return sboption.DomainStrategy(sbc.DomainStrategyPreferIPv6), nil
	}
	return 0, fmt.Errorf("unsupported DNSType %q", config.DNSType)
}

// directOptions binds outgoing connections to SendIP; an unspecified SendIP
// leaves the source to the system.
func (c *SingBoxController) directOptions(strategy sboption.DomainStrategy) (sboption.DirectOutboundOptions, error) {
	options := sboption.DirectOutboundOptions{DialerOptions: sboption.DialerOptions{AbstractDialerOptions: sboption.AbstractDialerOptions{
		DomainResolver: &sboption.DomainResolveOptions{Server: dnsServerTag, Strategy: strategy},
	}}}
	if c.config.SendIP == "" {
		return options, nil
	}
	addr, err := netip.ParseAddr(c.config.SendIP)
	if err != nil {
		return options, fmt.Errorf("invalid SendIP %q: %w", c.config.SendIP, err)
	}
	addr = addr.Unmap()
	bind := badoption.Addr(addr)
	switch {
	case addr.IsUnspecified():
	case addr.Is4():
		options.Inet4BindAddress = &bind
	default:
		options.Inet6BindAddress = &bind
	}
	return options, nil
}

// routeOptions sniffs every connection unless sniffing is off, as Xray nodes
// do: audit rules match the sniffed domain of a client that dialed an IP. It
// then resolves domains, so the guard sees the addresses direct will dial,
// and rejects BitTorrent (which takes sniffing).
func (c *SingBoxController) routeOptions(strategy sboption.DomainStrategy) *sboption.RouteOptions {
	var rules []sboption.Rule
	if !c.config.DisableSniffing {
		rules = append(rules, actionRule(sboption.RawDefaultRule{}, sboption.RuleAction{Action: sbc.RuleActionTypeSniff}))
	}
	rules = append(rules, actionRule(sboption.RawDefaultRule{}, sboption.RuleAction{
		Action:         sbc.RuleActionTypeResolve,
		ResolveOptions: sboption.RouteActionResolve{Server: dnsServerTag, Strategy: strategy},
	}))
	// Only the TCP handshake: the UDP uTP sniffer also takes WireGuard and
	// RakNet handshakes for BitTorrent, and Xray's never matched UDP at all.
	// Options built in code skip the JSON defaults; the router panics on an
	// empty reject method.
	rules = append(rules, actionRule(sboption.RawDefaultRule{
		Network:  badoption.Listable[string]{N.NetworkTCP},
		Protocol: badoption.Listable[string]{sbc.ProtocolBitTorrent},
	}, sboption.RuleAction{
		Action:        sbc.RuleActionTypeReject,
		RejectOptions: sboption.RejectActionOptions{Method: sbc.RuleActionRejectMethodDefault},
	}))
	return &sboption.RouteOptions{Rules: rules}
}

func actionRule(match sboption.RawDefaultRule, action sboption.RuleAction) sboption.Rule {
	return sboption.Rule{
		Type:           sbc.RuleTypeDefault,
		DefaultOptions: sboption.DefaultRule{RawDefaultRule: match, RuleAction: action},
	}
}

// trafficMonitor reports every counter with traffic on it, including users
// removed since the last report and names from before a rebuild, so their
// last stretch of traffic is not lost.
func (c *SingBoxController) trafficMonitor() error {
	if time.Since(c.startAt) < time.Duration(c.config.UpdatePeriodic)*time.Second {
		return nil
	}
	if online := c.guard.onlineUsers(); len(online) > 0 {
		if err := c.apiClient.ReportNodeOnlineUsers(&online); err != nil {
			c.logger.Print(err)
		}
	}
	type pending struct {
		counter  *userCounter
		up, down int64
	}
	// keeper keys a report by uid, so one uid counted under two names (a
	// rebuild moved the node tag, or the email changed) must be merged or
	// one of them would be dropped.
	byUID := make(map[int]int)
	var userTraffic []api.UserTraffic
	var reported []pending
	now := time.Now()
	for name, counter := range c.traffic.snapshot() {
		up, down := counter.up.Load(), counter.down.Load()
		if up == 0 && down == 0 {
			continue
		}
		uid, email, ok := parseUserTag(name)
		if !ok {
			c.logger.Warnf("drop traffic of unrecognized user %q", name)
			counter.up.Add(-up)
			counter.down.Add(-down)
			continue
		}
		c.logger.Debugf("Traffic counted: tag=%s up=%d down=%d", name, up, down)
		if index, loaded := byUID[uid]; loaded {
			userTraffic[index].Upload += up
			userTraffic[index].Download += down
		} else {
			byUID[uid] = len(userTraffic)
			userTraffic = append(userTraffic, api.UserTraffic{
				UID:      uid,
				Email:    email,
				Upload:   up,
				Download: down,
			})
		}
		reported = append(reported, pending{counter, up, down})
	}
	if c.autoLimit != nil {
		if limits, changed := c.autoLimit.observe(now, now.Sub(c.trafficSince), userTraffic); changed {
			c.guard.setAutoLimits(limits)
		}
	}

	if len(userTraffic) > 0 {
		c.logger.Printf("Reporting %d user(s) traffic to panel; example: UID=%d up=%d down=%d", len(userTraffic), userTraffic[0].UID, userTraffic[0].Upload, userTraffic[0].Download)
		if !c.config.DisableUploadTraffic {
			if err := c.apiClient.ReportUserTraffic(&userTraffic); err != nil {
				c.logger.Print(err)
				return nil
			}
		}
		// Subtract rather than zero: connections keep counting meanwhile.
		for _, p := range reported {
			p.counter.up.Add(-p.up)
			p.counter.down.Add(-p.down)
		}
	}
	c.trafficSince = now
	return nil
}
