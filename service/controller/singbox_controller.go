package controller

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"sync/atomic"
	"time"

	sb "github.com/sagernet/sing-box"
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
	log "github.com/sirupsen/logrus"
	"github.com/xtls/xray-core/common/task"

	"github.com/XrayR-project/XrayR/api"
)

type SingBoxController struct {
	config     *Config
	clientInfo api.ClientInfo
	apiClient  api.API
	nodeInfo   *api.NodeInfo

	Tag       string
	userList  *[]api.UserInfo
	tasks     []periodicTask
	jitter    jitterHolder
	panelType string

	startAt time.Time
	logger  *log.Entry

	box     *sb.Box
	traffic *singBoxTrafficTracker
}

func NewSingBoxController(apiClient api.API, config *Config, panelType string) *SingBoxController {
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
	c.nodeInfo = newNodeInfo
	c.Tag = c.buildNodeTag()

	userInfo, err := c.apiClient.GetUserList()
	if err != nil {
		return err
	}
	c.userList = userInfo

	err = c.startSingBox()
	if err != nil {
		return err
	}

	interval := time.Duration(c.config.UpdatePeriodic) * time.Second
	if interval <= 0 {
		interval = 60 * time.Second
	}

	// Fold a random delay into each poll/report so the node<->panel cadence
	// isn't a fixed-period beacon (see withJitter). sing-box nodes don't re-pull
	// /config, so panel jitter is read once here at start (node-local as
	// fallback); changing it in the panel takes effect on node restart.
	c.jitter.set(effectiveJitter(c.apiClient, c.config.UpdatePeriodicJitter))
	c.tasks = append(c.tasks, periodicTask{
		tag: "heartbeat",
		Periodic: &task.Periodic{
			Interval: interval,
			Execute:  withJitter(&c.jitter, c.heartbeatMonitor),
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

func (c *SingBoxController) heartbeatMonitor() error {
	if time.Since(c.startAt) < time.Duration(c.config.UpdatePeriodic)*time.Second {
		return nil
	}
	_, err := c.apiClient.GetUserList()
	if err != nil && err.Error() != api.UserNotModified {
		c.logger.Print(err)
	}
	return nil
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
	if c.box != nil {
		_ = c.box.Close()
		c.box = nil
	}
	return nil
}

func (c *SingBoxController) buildNodeTag() string {
	return fmt.Sprintf("%s_%s_%d", c.nodeInfo.NodeType, c.config.ListenIP, c.nodeInfo.Port)
}

func (c *SingBoxController) buildUserTag(user *api.UserInfo) string {
	return fmt.Sprintf("%s|%s|%d", c.Tag, user.Email, user.UID)
}

func (c *SingBoxController) startSingBox() error {
	nodeType := strings.ToLower(c.nodeInfo.NodeType)
	switch nodeType {
	case "anytls", "hysteria", "snell":
	default:
		return fmt.Errorf("unsupported node type for sing-box controller: %s", c.nodeInfo.NodeType)
	}
	if c.nodeInfo.Port > 65535 {
		return fmt.Errorf("invalid listen port: %d", c.nodeInfo.Port)
	}

	var listenAddr netip.Addr
	if c.config.ListenIP != "" {
		addr, err := netip.ParseAddr(c.config.ListenIP)
		if err != nil {
			return fmt.Errorf("invalid listen ip %q: %w", c.config.ListenIP, err)
		}
		listenAddr = addr
	} else {
		listenAddr = netip.IPv4Unspecified()
	}
	listenBadAddr := badoption.Addr(listenAddr)
	lo := sboption.ListenOptions{
		Listen:     &listenBadAddr,
		ListenPort: uint16(c.nodeInfo.Port),
	}

	var tlsOptions *sboption.InboundTLSOptions
	if c.nodeInfo.EnableTLS {
		if c.config.CertConfig == nil || c.config.CertConfig.CertMode == "none" {
			return fmt.Errorf("tls is required but CertConfig is not configured")
		}
		certFile, keyFile, err := getCertFile(c.config.CertConfig)
		if err != nil {
			return err
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
		users := make([]sboption.AnyTLSUser, 0, len(*c.userList))
		for _, user := range *c.userList {
			password := user.Passwd
			if password == "" {
				password = user.UUID
			}
			if password == "" {
				return fmt.Errorf("anytls user %d has empty password/uuid", user.UID)
			}
			users = append(users, sboption.AnyTLSUser{
				Name:     c.buildUserTag(&user),
				Password: password,
			})
		}
		anytlsOptions := &sboption.AnyTLSInboundOptions{
			ListenOptions: lo,
			InboundTLSOptionsContainer: sboption.InboundTLSOptionsContainer{
				TLS: tlsOptions,
			},
			Users: users,
		}
		if len(c.nodeInfo.PaddingScheme) > 0 {
			anytlsOptions.PaddingScheme = badoption.Listable[string](c.nodeInfo.PaddingScheme)
		}
		inboundType = sbc.TypeAnyTLS
		inboundOptions = anytlsOptions
	case "hysteria":
		// choose hy1 or hy2 by version, default hy2 when version==2
		version := c.nodeInfo.HysteriaVersion
		if version == 2 {
			sbhysteria2.RegisterInbound(inReg)
			users := make([]sboption.Hysteria2User, 0, len(*c.userList))
			for _, user := range *c.userList {
				password := user.Passwd
				if password == "" {
					password = user.UUID
				}
				if password == "" {
					return fmt.Errorf("hysteria2 user %d has empty password/uuid", user.UID)
				}
				users = append(users, sboption.Hysteria2User{
					Name:     c.buildUserTag(&user),
					Password: password,
				})
			}
			var obfs *sboption.Hysteria2Obfs
			if c.nodeInfo.HysteriaObfs != "" {
				obfs = &sboption.Hysteria2Obfs{
					Type:     c.nodeInfo.HysteriaObfs,
					Password: c.nodeInfo.HysteriaObfsPassword,
				}
			}
			h2Options := &sboption.Hysteria2InboundOptions{
				ListenOptions: lo,
				InboundTLSOptionsContainer: sboption.InboundTLSOptionsContainer{
					TLS: tlsOptions,
				},
				UpMbps:   c.nodeInfo.HysteriaUpMbps,
				DownMbps: c.nodeInfo.HysteriaDownMbps,
				Obfs:     obfs,
				Users:    users,
			}
			inboundType = sbc.TypeHysteria2
			inboundOptions = h2Options
		} else {
			sbhysteria.RegisterInbound(inReg)
			users := make([]sboption.HysteriaUser, 0, len(*c.userList))
			for _, user := range *c.userList {
				password := user.Passwd
				if password == "" {
					password = user.UUID
				}
				if password == "" {
					return fmt.Errorf("hysteria user %d has empty password/uuid", user.UID)
				}
				users = append(users, sboption.HysteriaUser{
					Name:       c.buildUserTag(&user),
					AuthString: password,
				})
			}
			hOptions := &sboption.HysteriaInboundOptions{
				ListenOptions: lo,
				InboundTLSOptionsContainer: sboption.InboundTLSOptionsContainer{
					TLS: tlsOptions,
				},
				UpMbps:   c.nodeInfo.HysteriaUpMbps,
				DownMbps: c.nodeInfo.HysteriaDownMbps,
				Obfs:     c.nodeInfo.HysteriaObfs,
				Users:    users,
			}
			inboundType = sbc.TypeHysteria
			inboundOptions = hOptions
		}
	case "snell":
		sbsnell.RegisterInbound(inReg)
		version := c.nodeInfo.SnellVersion
		// sing-box serves v5 and v6 only — its v4 support is client-side.
		// Reject here rather than let sing-snell fail deeper in with an error
		// the operator can't trace back to a panel field.
		if version != 5 && version != 6 {
			return fmt.Errorf("snell: unsupported version %d (sing-box serves 5 or 6)", version)
		}
		psk := c.nodeInfo.SnellPSK
		if psk == "" {
			return errors.New("snell: psk is required but the panel sent none")
		}
		// Mirrors snell-server v6's own check, which sing-snell reproduces.
		if version == 6 && (len(psk) < 12 || len(psk) > 255) {
			return fmt.Errorf("snell: v6 psk must be 12-255 bytes, panel sent %d", len(psk))
		}

		snellOptions := &sboption.SnellInboundOptions{
			ListenOptions: lo,
			Version:       version,
			PSK:           psk,
		}
		if version == 6 {
			snellOptions.V6Options = sboption.SnellV6Options{Mode: c.nodeInfo.SnellMode}
		} else {
			snellOptions.ObfsOptions = sboption.SnellObfsServerOptions{ObfsMode: c.nodeInfo.SnellObfs}
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
		if c.nodeInfo.SnellMultiUser {
			// v5 + multi_user is a node no client can reach, so refuse to boot
			// one rather than let it sit there looking healthy: official Surge
			// speaks v5 but cannot send a client-id, and the only clients that
			// can send one are sing-box-family — which implement no v5 client
			// at all (sing-snell ships snellv5/server.go with no client.go).
			if version == 5 {
				return errors.New("snell: version 5 with multi_user has no reachable client — Surge cannot send a client-id and sing-box has no v5 client. Use version 6, or turn multi_user off")
			}
			// sing-box picks the service implementation off len(Users): an
			// empty list builds the SHARED-PSK service, not a multi-user one
			// that admits nobody. Booting here would silently invert the
			// operator's intent — any psk holder connects, nobody is metered.
			// keeper's GetUserList already errors on an empty list ("users is
			// null"), but that invariant lives a repo away; pin it locally.
			if len(*c.userList) == 0 {
				return errors.New("snell: multi_user is on but the panel sent zero users — refusing to boot: sing-box would fall back to shared-psk mode and admit any psk holder unmetered")
			}
			users := make([]sboption.SnellUser, 0, len(*c.userList))
			for _, user := range *c.userList {
				key := user.Passwd
				if key == "" {
					key = user.UUID
				}
				if key == "" {
					return fmt.Errorf("snell user %d has empty password/uuid", user.UID)
				}
				users = append(users, sboption.SnellUser{
					Name:    c.buildUserTag(&user),
					UserKey: key,
				})
			}
			snellOptions.Users = users
		} else {
			c.logger.Warn("snell: shared-psk mode — all users share the node psk, so no traffic can be attributed and this node will report zero usage to the panel. Set multi_user on the node to meter users (note: official Surge clients cannot connect in that mode).")
		}

		inboundType = sbc.TypeSnell
		inboundOptions = snellOptions
	}

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
		sboutbound.NewRegistry(),
		sbendpoint.NewRegistry(),
		dnsTransportReg,
		sbservice.NewRegistry(),
		// sing-box v1.14 added a certificate-provider registry to the context.
		// We issue no certificates from providers (CertConfig hands us files on
		// disk), but box.New dereferences the registry, so it must be present.
		sbcertificate.NewRegistry(),
	)

	traffic := newSingBoxTrafficTracker(c.logger)
	options := sb.Options{
		Options: sboption.Options{
			Log: &sboption.LogOptions{
				Disabled: true,
			},
			Inbounds: []sboption.Inbound{
				{
					Type:    inboundType,
					Tag:     c.Tag,
					Options: inboundOptions,
				},
			},
		},
		Context: ctx,
	}

	boxInstance, err := sb.New(options)
	if err != nil {
		return err
	}
	boxInstance.Router().AppendTracker(traffic)
	if err := boxInstance.Start(); err != nil {
		_ = boxInstance.Close()
		return err
	}
	c.box = boxInstance
	c.traffic = traffic
	return nil
}

func (c *SingBoxController) getTraffic(userTag string) (up int64, down int64, upCounter *atomic.Int64, downCounter *atomic.Int64) {
	upName := "user>>>" + userTag + ">>>traffic>>>uplink"
	downName := "user>>>" + userTag + ">>>traffic>>>downlink"
	upCounter = c.traffic.GetCounter(upName)
	downCounter = c.traffic.GetCounter(downName)
	if upCounter != nil && upCounter.Load() != 0 {
		up = upCounter.Load()
	} else {
		upCounter = nil
	}
	if downCounter != nil && downCounter.Load() != 0 {
		down = downCounter.Load()
	} else {
		downCounter = nil
	}
	return up, down, upCounter, downCounter
}

func (c *SingBoxController) resetTraffic(upCounterList *[]*atomic.Int64, downCounterList *[]*atomic.Int64) {
	for _, upCounter := range *upCounterList {
		upCounter.Store(0)
	}
	for _, downCounter := range *downCounterList {
		downCounter.Store(0)
	}
}

func (c *SingBoxController) trafficMonitor() (err error) {
	if time.Since(c.startAt) < time.Duration(c.config.UpdatePeriodic)*time.Second {
		return nil
	}
	if c.traffic == nil || c.userList == nil {
		return nil
	}

	var userTraffic []api.UserTraffic
	var upCounterList []*atomic.Int64
	var downCounterList []*atomic.Int64

	for _, user := range *c.userList {
		userTag := c.buildUserTag(&user)
		up, down, upCounter, downCounter := c.getTraffic(userTag)
		if down > 0 {
			c.logger.Printf("Traffic counted: tag=%s up=%d down=%d", userTag, up, down)
		}
		if up > 0 || down > 0 {
			userTraffic = append(userTraffic, api.UserTraffic{
				UID:      user.UID,
				Email:    user.Email,
				Upload:   up,
				Download: down,
			})
			if upCounter != nil {
				upCounterList = append(upCounterList, upCounter)
			}
			if downCounter != nil {
				downCounterList = append(downCounterList, downCounter)
			}
		}
	}

	if len(userTraffic) > 0 {
		c.logger.Printf("Reporting %d user(s) traffic to panel; example: UID=%d up=%d down=%d", len(userTraffic), userTraffic[0].UID, userTraffic[0].Upload, userTraffic[0].Download)
		var reportErr error
		if !c.config.DisableUploadTraffic {
			reportErr = c.apiClient.ReportUserTraffic(&userTraffic)
		}
		if reportErr != nil {
			c.logger.Print(reportErr)
		} else {
			c.resetTraffic(&upCounterList, &downCounterList)
		}
	}

	return nil
}
