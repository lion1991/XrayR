package newV2board

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
		PushInterval int `json:"push_interval"`
		PullInterval int `json:"pull_interval"`
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
		xVer       uint64 `json:"xver"`
		Sni        string `json:"server_name"`
		PrivateKey string `json:"private_key"`
		ShortId    string `json:"short_id"`
	} `json:"tls_settings"`
	Tls int `json:"tls"`
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
