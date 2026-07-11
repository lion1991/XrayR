package keeper

import (
	"encoding/json"
)

type serverConfig struct {
	shadowsocks
	v2ray
	trojan
	anytls
	hysteria
	snell

	// Obfs is declared at the outer level on purpose — `shadowsocks` and
	// `hysteria` both define an embedded `Obfs string \`json:"obfs"\``
	// field, and Go's encoding/json ignores keys whose target is
	// ambiguous between two same-depth embedded fields. By shadowing them
	// from a less-deep struct level, this single field captures the JSON
	// `obfs` value for whichever protocol the node speaks (they are
	// mutually exclusive in practice). `snell` deliberately embeds no obfs
	// field of its own and is parsed off this outer one too — adding one
	// there would be harmless but pointless (it could never populate).
	Obfs string `json:"obfs"`

	// Version is hoisted here for exactly the same reason, and the stakes are
	// higher: `hysteria` and `snell` both carry a `version` key, so leaving one
	// in each embedded struct would make encoding/json silently drop BOTH — and
	// a Hysteria node whose version decodes to 0 instead of 2 quietly downgrades
	// itself from Hy2 to Hy1 rather than failing. One field, one level up.
	Version int `json:"version"`

	ServerPort int `json:"server_port"`
	BaseConfig struct {
		PushInterval   int `json:"push_interval"`
		PullInterval   int `json:"pull_interval"`
		IntervalJitter int `json:"interval_jitter"`
	} `json:"base_config"`
	Routes []route `json:"routes"`
}

type shadowsocks struct {
	Cipher       string `json:"cipher"`
	Obfs         string `json:"obfs"`
	ObfsSettings struct {
		Path string `json:"path"`
		Host string `json:"host"`
	} `json:"obfs_settings"`
	ServerKey string `json:"server_key"`
}

type v2ray struct {
	Network         string `json:"network"`
	NetworkSettings struct {
		Path        string           `json:"path"`
		Host        string           `json:"host"`
		Headers     *json.RawMessage `json:"headers"`
		ServiceName string           `json:"serviceName"`
		Header      *json.RawMessage `json:"header"`
	} `json:"networkSettings"`
	VlessNetworkSettings struct {
		Path        string           `json:"path"`
		Host        string           `json:"host"`
		Headers     *json.RawMessage `json:"headers"`
		ServiceName string           `json:"serviceName"`
		Header      *json.RawMessage `json:"header"`
	} `json:"network_settings"`
	VlessFlow        string `json:"flow"`
	VlessTlsSettings struct {
		ServerPort string `json:"server_port"`
		Dest       string `json:"dest"`
		// Xver MUST stay exported: encoding/json silently skips unexported
		// fields, so the old `xVer` lowercase name made the panel's xver
		// always decode to 0 (latent bug). Keep it capitalized.
		Xver                  uint64         `json:"xver"`
		Sni                   string         `json:"server_name"`  // legacy single SNI
		ServerNames           []string       `json:"server_names"` // plural wins when non-empty
		PrivateKey            string         `json:"private_key"`
		ShortId               string         `json:"short_id"`  // legacy single shortId
		ShortIds              []string       `json:"short_ids"` // plural wins when non-empty
		MinClientVer          string         `json:"min_client_ver"`
		MaxClientVer          string         `json:"max_client_ver"`
		MaxTimeDiff           uint64         `json:"max_time_diff"`
		Show                  bool           `json:"show"`
		Mldsa65Seed           string         `json:"mldsa65_seed"`
		LimitFallbackUpload   *limitFallback `json:"limit_fallback_upload"`
		LimitFallbackDownload *limitFallback `json:"limit_fallback_download"`
	} `json:"tls_settings"`
	Tls int `json:"tls"`
}

// limitFallback mirrors xray-core's reality LimitFallback so the panel can
// drive per-connection fallback rate limits. All fields optional.
type limitFallback struct {
	AfterBytes       uint64 `json:"after_bytes"`
	BytesPerSec      uint64 `json:"bytes_per_sec"`
	BurstBytesPerSec uint64 `json:"burst_bytes_per_sec"`
}

type trojan struct {
	Host       string `json:"host"`
	ServerName string `json:"server_name"`
}

type anytls struct {
	AnyTLSServerName string   `json:"server_name"`
	PaddingScheme    []string `json:"padding_scheme"`
}

type hysteria struct {
	HysteriaServerName string `json:"server_name"`
	UpMbps             int    `json:"up_mbps"`
	DownMbps           int    `json:"down_mbps"`
	HysteriaObfs       string `json:"obfs"`
	HysteriaObfsPwd    string `json:"obfs-password"`
}

// snell holds the node-level Snell parameters. Snell has neither TLS nor a
// pluggable transport, so this is the whole node config: a shared psk, plus
// either `mode` (v6 traffic shaping) or `obfs` (v5 obfuscation, read off the
// outer Obfs field above).
//
// MultiUser selects the user model. It is a protocol fork, not a tuning knob:
// Snell carries the per-user key in the request's ClientID field, which the
// official Surge client never sends. See the Snell case in
// service/controller/singbox_controller.go.
type snell struct {
	PSK       string `json:"psk"`
	SnellMode string `json:"mode"`
	MultiUser bool   `json:"multi_user"`
}

type route struct {
	Id          int      `json:"id"`
	Match       []string `json:"match"`
	Action      string   `json:"action"`
	ActionValue string   `json:"action_value"`
}

type user struct {
	Id         int    `json:"id"`
	Uuid       string `json:"uuid"`
	SpeedLimit int    `json:"speed_limit"`
}
