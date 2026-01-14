package controller

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"sync/atomic"
	"time"

	sb "github.com/sagernet/sing-box"
	sbendpoint "github.com/sagernet/sing-box/adapter/endpoint"
	sbinbound "github.com/sagernet/sing-box/adapter/inbound"
	sboutbound "github.com/sagernet/sing-box/adapter/outbound"
	sbservice "github.com/sagernet/sing-box/adapter/service"
	sbc "github.com/sagernet/sing-box/constant"
	sbdns "github.com/sagernet/sing-box/dns"
	sboption "github.com/sagernet/sing-box/option"
	sbanytls "github.com/sagernet/sing-box/protocol/anytls"
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

	c.tasks = append(c.tasks, periodicTask{
		tag: "heartbeat",
		Periodic: &task.Periodic{
			Interval: interval,
			Execute:  c.heartbeatMonitor,
		},
	})
	c.tasks = append(c.tasks, periodicTask{
		tag: "traffic monitor",
		Periodic: &task.Periodic{
			Interval: interval,
			Execute:  c.trafficMonitor,
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
	if c.nodeInfo.NodeType != "AnyTLS" {
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
			return fmt.Errorf("anytls requires tls but CertConfig is not configured")
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

	inboundOptions := &sboption.AnyTLSInboundOptions{
		ListenOptions: lo,
		InboundTLSOptionsContainer: sboption.InboundTLSOptionsContainer{
			TLS: tlsOptions,
		},
		Users: users,
	}
	if len(c.nodeInfo.PaddingScheme) > 0 {
		inboundOptions.PaddingScheme = badoption.Listable[string](c.nodeInfo.PaddingScheme)
	}

	inReg := sbinbound.NewRegistry()
	sbanytls.RegisterInbound(inReg)

	ctx := context.Background()
	ctx = sb.Context(
		ctx,
		inReg,
		sboutbound.NewRegistry(),
		sbendpoint.NewRegistry(),
		sbdns.NewTransportRegistry(),
		sbservice.NewRegistry(),
	)

	traffic := newSingBoxTrafficTracker(c.logger)
	options := sb.Options{
		Options: sboption.Options{
			Log: &sboption.LogOptions{
				Disabled: true,
			},
			Inbounds: []sboption.Inbound{
				{
					Type:    sbc.TypeAnyTLS,
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
