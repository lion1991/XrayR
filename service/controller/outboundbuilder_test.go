package controller_test

import (
	"testing"

	"github.com/XrayR-project/XrayR/api"
	. "github.com/XrayR-project/XrayR/service/controller"
)

// TestOutboundBuilderOmittedSendIP verifies a node can omit SendIP: an empty
// SendIP must not be handed to xray-core as a blank send-through. Both an unset
// and a set SendIP must build without error.
func TestOutboundBuilderOmittedSendIP(t *testing.T) {
	nodeInfo := &api.NodeInfo{NodeType: "V2ray", NodeID: 1, Port: 443}

	if _, err := OutboundBuilder(&Config{}, nodeInfo, "test_tag"); err != nil {
		t.Errorf("omitted SendIP: %v", err)
	}
	if _, err := OutboundBuilder(&Config{SendIP: "0.0.0.0"}, nodeInfo, "test_tag"); err != nil {
		t.Errorf("explicit SendIP: %v", err)
	}
}
