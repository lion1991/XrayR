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

	// Obfs is declared at the outer level on purpose — both `shadowsocks`
	// and `hysteria` define an embedded `Obfs string \`json:"obfs"\``
	// field, and Go's encoding/json ignores keys whose target is
	// ambiguous between two same-depth embedded fields. By shadowing them
	// from a less-deep struct level, this single field captures the JSON
	// `obfs` value for whichever protocol the node speaks (the two are
	// mutually exclusive in practice).
	Obfs string `json:"obfs"`

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
	Version            int    `json:"version"`
	HysteriaServerName string `json:"server_name"`
	UpMbps             int    `json:"up_mbps"`
	DownMbps           int    `json:"down_mbps"`
	HysteriaObfs       string `json:"obfs"`
	HysteriaObfsPwd    string `json:"obfs-password"`
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
