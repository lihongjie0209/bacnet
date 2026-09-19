package npdu

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/worldiety/bacnet/common/netprim"
)

type nlmConformanceVector struct {
	name  string
	wire  []byte
	valid bool
}

func loadNLMConformanceVectors(t *testing.T) []nlmConformanceVector {
	t.Helper()

	path := filepath.Join("..", "testdata", "npdu", "nlm_vectors.txt")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read fixture file: %v", err)
	}

	lines := strings.Split(string(raw), "\n")
	vectors := make([]nlmConformanceVector, 0, len(lines))
	for i, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.Split(line, "|")
		if len(parts) != 3 {
			t.Fatalf("invalid fixture format on line %d: %q", i+1, line)
		}
		wire, err := hex.DecodeString(parts[1])
		if err != nil {
			t.Fatalf("invalid hex on line %d: %v", i+1, err)
		}
		valid := false
		switch parts[2] {
		case "true":
			valid = true
		case "false":
			valid = false
		default:
			t.Fatalf("invalid valid-flag on line %d: %q", i+1, parts[2])
		}
		vectors = append(vectors, nlmConformanceVector{name: parts[0], wire: wire, valid: valid})
	}

	return vectors
}

func buildMessageForConformanceVector(name string) (NetworkLayerMessageModel, error) {
	switch name {
	case "valid_00_who_is_router_any":
		return NewWhoIsRouterToNetworkMessage(nil)
	case "valid_00_who_is_router_dnet_100":
		return NewWhoIsRouterToNetworkMessage(ptr(netprim.NetworkNumber(100)))
	case "valid_01_i_am_router":
		return NewIAmRouterToNetworkMessage([]netprim.NetworkNumber{100, 200})
	case "valid_02_i_could_be_router":
		return NewICouldBeRouterToNetworkMessage(100, 5)
	case "valid_03_reject_message":
		return NewRejectMessageToNetworkMessage(100, NLMRejectReasonTooManyHops)
	case "valid_04_router_busy":
		return NewRouterBusyToNetworkMessage([]netprim.NetworkNumber{100})
	case "valid_05_router_available":
		return NewRouterAvailableToNetworkMessage([]netprim.NetworkNumber{100, 200})
	case "valid_06_initialize_routing_table":
		entry, err := NewRoutingTablePortEntry(100, 0x11, []byte{0xAA, 0xBB})
		if err != nil {
			return nil, err
		}
		return NewInitializeRoutingTableMessage([]RoutingTablePortEntry{entry})
	case "valid_07_initialize_routing_table_ack":
		entry, err := NewRoutingTablePortEntry(101, 0x12, []byte{0xAB})
		if err != nil {
			return nil, err
		}
		return NewInitializeRoutingTableAckMessage([]RoutingTablePortEntry{entry})
	case "valid_08_establish_connection":
		return NewEstablishConnectionToNetworkMessage(100, 30)
	case "valid_09_disconnect_connection":
		return NewDisconnectConnectionToNetworkMessage(100)
	case "valid_12_what_is_network_number":
		return NewWhatIsNetworkNumberMessage()
	case "valid_13_network_number_is":
		return NewNetworkNumberIsMessage(100, true)
	case "valid_80_proprietary":
		return NewProprietaryNetworkLayerMessageModel(NetworkLayerMessageTypeVendorProprietary, 0x1234, []byte{0xDE, 0xAD})
	default:
		return nil, fmt.Errorf("no model builder for vector %q", name)
	}
}

func TestNLMConformanceVectorsWireCodec(t *testing.T) {
	vectors := loadNLMConformanceVectors(t)

	for _, v := range vectors {
		t.Run(v.name, func(t *testing.T) {
			decoded, err := DecodeNetworkLayerMessageWire(v.wire)
			if !v.valid {
				if err == nil {
					t.Fatalf("DecodeNetworkLayerMessageWire() expected error")
				}
				return
			}
			if err != nil {
				t.Fatalf("DecodeNetworkLayerMessageWire(): %v", err)
			}

			expected, err := buildMessageForConformanceVector(v.name)
			if err != nil {
				t.Fatalf("buildMessageForConformanceVector(): %v", err)
			}

			encoded, err := EncodeNetworkLayerMessageWire(expected)
			if err != nil {
				t.Fatalf("EncodeNetworkLayerMessageWire(): %v", err)
			}
			if !bytes.Equal(encoded, v.wire) {
				t.Fatalf("encoded wire = %#v, want %#v", encoded, v.wire)
			}

			reEncoded, err := EncodeNetworkLayerMessageWire(decoded)
			if err != nil {
				t.Fatalf("EncodeNetworkLayerMessageWire(decoded): %v", err)
			}
			if !bytes.Equal(reEncoded, v.wire) {
				t.Fatalf("re-encoded wire = %#v, want %#v", reEncoded, v.wire)
			}
		})
	}
}

func TestNLMConformanceVectorsNPDUPayload(t *testing.T) {
	vectors := loadNLMConformanceVectors(t)

	for _, v := range vectors {
		if !v.valid {
			continue
		}
		t.Run(v.name, func(t *testing.T) {
			model, err := buildMessageForConformanceVector(v.name)
			if err != nil {
				t.Fatalf("buildMessageForConformanceVector(): %v", err)
			}

			n, err := NewNetworkLayerNPDUFromMessage(NPCI{Priority: netprim.NetworkPriorityNormal}, model)
			if err != nil {
				t.Fatalf("NewNetworkLayerNPDUFromMessage(): %v", err)
			}

			header := n.MustNetworkLayerMessageHeader()
			offset := 1
			if header.VendorID != nil {
				offset += 2
			}
			if !bytes.Equal(n.NetworkLayerPayloadBytes(), v.wire[offset:]) {
				t.Fatalf("npdu payload = %#v, want %#v", n.NetworkLayerPayloadBytes(), v.wire[offset:])
			}
		})
	}
}
