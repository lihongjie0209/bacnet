package apdu

import (
	"testing"

	"github.com/worldiety/bacnet/common/netprim"
)

// --- NetworkPriority ---

func TestNetworkPriorityString(t *testing.T) {
	tests := []struct {
		p    netprim.NetworkPriority
		want string
	}{
		{netprim.NetworkPriorityNormal, "normal"},
		{netprim.NetworkPriorityUrgent, "urgent"},
		{netprim.NetworkPriorityCriticalEquipment, "critical-equipment"},
		{netprim.NetworkPriorityLifeSafety, "life-safety"},
		{netprim.NetworkPriority(4), "network-priority(4)"},
		{netprim.NetworkPriority(255), "network-priority(255)"},
	}
	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			if got := tt.p.String(); got != tt.want {
				t.Errorf("String() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestNetworkPriorityValid(t *testing.T) {
	tests := []struct {
		p    netprim.NetworkPriority
		want bool
	}{
		{netprim.NetworkPriorityNormal, true},
		{netprim.NetworkPriorityUrgent, true},
		{netprim.NetworkPriorityCriticalEquipment, true},
		{netprim.NetworkPriorityLifeSafety, true},
		{netprim.NetworkPriority(4), false},
		{netprim.NetworkPriority(255), false},
	}
	for _, tt := range tests {
		t.Run(tt.p.String(), func(t *testing.T) {
			if got := tt.p.Valid(); got != tt.want {
				t.Errorf("Valid() = %v, want %v", got, tt.want)
			}
		})
	}
}

// --- MaxSegmentsAccepted ---

func TestMaxSegmentsAcceptedString(t *testing.T) {
	tests := []struct {
		m    MaxSegmentsAccepted
		want string
	}{
		{MaxSegmentsUnspecified, "unspecified"},
		{MaxSegments2, "2"},
		{MaxSegments4, "4"},
		{MaxSegments8, "8"},
		{MaxSegments16, "16"},
		{MaxSegments32, "32"},
		{MaxSegments64, "64"},
		{MaxSegmentsMoreThan64, "more-than-64"},
		{MaxSegmentsAccepted(8), "8"},
	}
	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			if got := tt.m.String(); got != tt.want {
				t.Errorf("String() = %q, want %q", got, tt.want)
			}
		})
	}
}

// --- ConfirmResult ---

func TestConfirmResultString(t *testing.T) {
	tests := []struct {
		r    ConfirmResult
		want string
	}{
		{ConfirmResultPositiveAck, "positive-ack"},
		{ConfirmResultError, "error"},
		{ConfirmResultReject, "reject"},
		{ConfirmResultAbort, "abort"},
		{ConfirmResultCannotSend, "cannot-send"},
		{ConfirmResultUnexpectedPDU, "unexpected-pdu"},
		{ConfirmResultSecurityError, "security-error"},
		{ConfirmResult(7), "confirm-result(7)"},
	}
	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			if got := tt.r.String(); got != tt.want {
				t.Errorf("String() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestConfirmedResponseTypeString(t *testing.T) {
	tests := []struct {
		r    ConfirmedResponseType
		want string
	}{
		{ConfirmedResponseTypeACK, "ack"},
		{ConfirmedResponseTypeError, "error"},
		{ConfirmedResponseTypeReject, "reject"},
		{ConfirmedResponseTypeAbort, "abort"},
		{ConfirmedResponseType(9), "confirmed-response-type(9)"},
	}

	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			if got := tt.r.String(); got != tt.want {
				t.Errorf("String() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestServiceChoiceString(t *testing.T) {
	tests := []struct {
		choice ServiceChoice
		want   string
	}{
		{ServiceChoiceIAm, "i-am"},
		{ServiceChoiceIHave, "i-have"},
		{ServiceChoiceUnconfirmedCOVNotification, "unconfirmed-cov-notification"},
		{ServiceChoiceUnconfirmedEventNotification, "unconfirmed-event-notification"},
		{ServiceChoiceUnconfirmedPrivateTransfer, "unconfirmed-private-transfer"},
		{ServiceChoiceUnconfirmedTextMessage, "unconfirmed-text-message"},
		{ServiceChoiceWhoHas, "who-has"},
		{ServiceChoiceWhoIs, "who-is"},
		{ServiceChoiceTimeSynchronization, "time-synchronization"},
		{ServiceChoiceUTCTimeSynchronization, "utc-time-synchronization"},
		{ServiceChoiceWriteGroup, "write-group"},
		{ServiceChoiceUnconfirmedCOVNotificationMultiple, "unconfirmed-cov-notification-multiple"},
		{ServiceChoiceReadProperty, "read-property"},
		{ServiceChoiceReadPropertyConditional, "read-property-conditional"},
		{ServiceChoiceReadPropertyMultiple, "read-property-multiple"},
		{ServiceChoiceWriteProperty, "write-property"},
		{ServiceChoiceWritePropertyMultiple, "write-property-multiple"},
		{ServiceChoiceVTOpen, "vt-open"},
		{ServiceChoiceVTClose, "vt-close"},
		{ServiceChoiceVTData, "vt-data"},
		{ServiceChoiceAuthenticate, "authenticate"},
		{ServiceChoiceRequestKey, "request-key"},
		{ServiceChoiceReadRange, "read-range"},
		{ServiceChoiceLifeSafetyOperation, "life-safety-operation"},
		{ServiceChoiceGetEventInformation, "get-event-information"},
		{ServiceChoiceSubscribeCOVPropertyMultiple, "subscribe-cov-property-multiple"},
		{ServiceChoice(255), "service-choice(255)"},
	}

	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			if got := tt.choice.String(); got != tt.want {
				t.Errorf("String() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestServiceChoiceClassifiers(t *testing.T) {
	confirmed := []ServiceChoice{
		ServiceChoiceConfirmedCOVNotification,
		ServiceChoiceSubscribeCOV,
		ServiceChoiceReadProperty,
		ServiceChoiceReadPropertyConditional,
		ServiceChoiceReadPropertyMultiple,
		ServiceChoiceWriteProperty,
		ServiceChoiceWritePropertyMultiple,
		ServiceChoiceDeviceCommunicationControl,
		ServiceChoiceConfirmedPrivateTransfer,
		ServiceChoiceConfirmedTextMessage,
		ServiceChoiceReinitializeDevice,
		ServiceChoiceVTOpen,
		ServiceChoiceVTClose,
		ServiceChoiceVTData,
		ServiceChoiceAuthenticate,
		ServiceChoiceRequestKey,
		ServiceChoiceReadRange,
		ServiceChoiceLifeSafetyOperation,
		ServiceChoiceSubscribeCOVProperty,
		ServiceChoiceGetEventInformation,
		ServiceChoiceSubscribeCOVPropertyMultiple,
	}
	for _, choice := range confirmed {
		t.Run("confirmed-"+choice.String(), func(t *testing.T) {
			if !IsConfirmedServiceChoice(choice) {
				t.Fatalf("IsConfirmedServiceChoice(%v) = false, want true", choice)
			}
			if choice != ServiceChoiceSubscribeCOV && choice != ServiceChoiceConfirmedCOVNotification && IsUnconfirmedServiceChoice(choice) {
				t.Fatalf("IsUnconfirmedServiceChoice(%v) = true, want false", choice)
			}
		})
	}

	unconfirmed := []ServiceChoice{
		ServiceChoiceIAm,
		ServiceChoiceIHave,
		ServiceChoiceUnconfirmedCOVNotification,
		ServiceChoiceUnconfirmedEventNotification,
		ServiceChoiceUnconfirmedPrivateTransfer,
		ServiceChoiceUnconfirmedTextMessage,
		ServiceChoiceTimeSynchronization,
		ServiceChoiceWhoHas,
		ServiceChoiceWhoIs,
		ServiceChoiceUTCTimeSynchronization,
		ServiceChoiceWriteGroup,
		ServiceChoiceUnconfirmedCOVNotificationMultiple,
	}
	for _, choice := range unconfirmed {
		t.Run("unconfirmed-"+choice.String(), func(t *testing.T) {
			if !IsUnconfirmedServiceChoice(choice) {
				t.Fatalf("IsUnconfirmedServiceChoice(%v) = false, want true", choice)
			}
			if choice != ServiceChoiceUnconfirmedTextMessage && choice != ServiceChoiceIHave && IsConfirmedServiceChoice(choice) {
				t.Fatalf("IsConfirmedServiceChoice(%v) = true, want false", choice)
			}
		})
	}

	if IsConfirmedServiceChoice(ServiceChoice(255)) {
		t.Fatal("IsConfirmedServiceChoice(255) = true, want false")
	}
	if IsUnconfirmedServiceChoice(ServiceChoice(255)) {
		t.Fatal("IsUnconfirmedServiceChoice(255) = true, want false")
	}
}

// --- ICI struct field access ---

func TestConfirmedRequestICIFields(t *testing.T) {
	dst, _ := netprim.NewAddress(netprim.LocalNetwork, []byte{0x01})
	ici := ConfirmedRequestICI{
		Destination:           dst,
		MaxAPDULengthAccepted: 1476,
		SegmentationSupported: SegmentationSupportBoth,
		MaxSegmentsAccepted:   MaxSegments16,
		Priority:              netprim.NetworkPriorityUrgent,
		ServiceRequest: ConfirmedRequest{
			ServiceChoice: ServiceChoiceReadProperty,
			Payload:       []byte{0x0C, 0x02},
		},
	}

	if !ici.Priority.Valid() {
		t.Error("Priority.Valid() = false, want true")
	}

	if ici.MaxAPDULengthAccepted != 1476 {
		t.Errorf("MaxAPDULengthAccepted = %d, want 1476", ici.MaxAPDULengthAccepted)
	}

	if ici.SegmentationSupported != SegmentationSupportBoth {
		t.Errorf("SegmentationSupported = %v, want %v", ici.SegmentationSupported, SegmentationSupportBoth)
	}

	if ici.ServiceRequest.ServiceChoice != ServiceChoiceReadProperty {
		t.Errorf("ServiceChoice = %v, want %v", ici.ServiceRequest.ServiceChoice, ServiceChoiceReadProperty)
	}

	if len(ici.ServiceRequest.Payload) != 2 {
		t.Errorf("Payload length = %d, want 2", len(ici.ServiceRequest.Payload))
	}
}

func TestUnconfirmedRequestICIFields(t *testing.T) {
	dst, _ := netprim.NewAddress(netprim.LocalNetwork, []byte{0xFF})
	ici := UnconfirmedRequestICI{
		Destination: dst,
		Priority:    netprim.NetworkPriorityNormal,
		ServiceRequest: UnconfirmedRequest{
			ServiceChoice: ServiceChoiceWhoIs,
			Payload:       []byte{0x00, 0xFF},
		},
	}

	if ici.Priority != netprim.NetworkPriorityNormal {
		t.Errorf("Priority = %v, want %v", ici.Priority, netprim.NetworkPriorityNormal)
	}
	if ici.ServiceRequest.ServiceChoice != ServiceChoiceWhoIs {
		t.Errorf("ServiceChoice = %v, want %v", ici.ServiceRequest.ServiceChoice, ServiceChoiceWhoIs)
	}
}

func TestConfirmedIndicationICIDataExpectingReply(t *testing.T) {
	src, _ := netprim.NewAddress(netprim.LocalNetwork, []byte{0x02})
	ici := ConfirmedIndicationICI{
		Source:                src,
		InvokeID:              InvokeID(42),
		MaxAPDULengthAccepted: 1476,
		SegmentationSupported: SegmentationSupportNo,
		MaxSegmentsAccepted:   MaxSegmentsUnspecified,
		Priority:              netprim.NetworkPriorityNormal,
		DataExpectingReply:    true, // always true for confirmed services
		ServiceRequest: ConfirmedRequest{
			ServiceChoice: ServiceChoiceReadProperty,
			Payload:       []byte{0x0C},
		},
	}

	if ici.InvokeID != 42 {
		t.Errorf("InvokeID = %d, want 42", ici.InvokeID)
	}
	if !ici.DataExpectingReply {
		t.Error("DataExpectingReply = false; confirmed service indications always expect a reply")
	}
	if ici.MaxSegmentsAccepted != MaxSegmentsUnspecified {
		t.Errorf("MaxSegmentsAccepted = %v, want %v", ici.MaxSegmentsAccepted, MaxSegmentsUnspecified)
	}
}

func TestUnconfirmedIndicationICIFields(t *testing.T) {
	src, _ := netprim.NewAddress(netprim.LocalNetwork, []byte{0x03})
	ici := UnconfirmedIndicationICI{
		Source:   src,
		Priority: netprim.NetworkPriorityNormal,
		ServiceRequest: UnconfirmedRequest{
			ServiceChoice: ServiceChoiceIAm,
			Payload:       []byte{0xDE, 0xAD},
		},
	}

	if ici.ServiceRequest.ServiceChoice != ServiceChoiceIAm {
		t.Errorf("ServiceChoice = %v, want %v", ici.ServiceRequest.ServiceChoice, ServiceChoiceIAm)
	}
	if len(ici.ServiceRequest.Payload) != 2 {
		t.Errorf("Payload length = %d, want 2", len(ici.ServiceRequest.Payload))
	}
}

func TestConfirmedResponseICIFields(t *testing.T) {
	dst, _ := netprim.NewAddress(netprim.LocalNetwork, []byte{0x04})
	ici := ConfirmedResponseICI{
		Destination:           dst,
		InvokeID:              InvokeID(7),
		SegmentationSupported: SegmentationSupportBoth,
		ServiceResponse:       ServiceResult{Payload: []byte{0x42, 0x43}},
	}

	if ici.InvokeID != 7 {
		t.Errorf("InvokeID = %d, want 7", ici.InvokeID)
	}
	if ici.SegmentationSupported != SegmentationSupportBoth {
		t.Errorf("SegmentationSupported = %v, want %v", ici.SegmentationSupported, SegmentationSupportBoth)
	}
	if len(ici.ServiceResponse.Payload) != 2 || ici.ServiceResponse.Payload[0] != 0x42 {
		t.Errorf("ServiceResponse.Payload = %v, want [0x42 0x43]", ici.ServiceResponse.Payload)
	}
}

func TestConfirmICIPositiveAck(t *testing.T) {
	resp := ServiceResult{Payload: []byte{0xBB}}
	ici := ConfirmICI{
		InvokeID:        InvokeID(3),
		Result:          ConfirmResultPositiveAck,
		ServiceResponse: &resp,
	}

	if ici.Result != ConfirmResultPositiveAck {
		t.Errorf("Result = %v, want %v", ici.Result, ConfirmResultPositiveAck)
	}
	if ici.ServiceResponse == nil {
		t.Fatal("ServiceResponse is nil, want non-nil for positive-ack")
	}
	if ici.ServiceResponse.Payload[0] != 0xBB {
		t.Errorf("ServiceResponse.Payload[0] = 0x%02X, want 0xBB", ici.ServiceResponse.Payload[0])
	}
}

func TestConfirmICINonPositiveAckNilServiceResponse(t *testing.T) {
	// For Error, Reject, and Abort outcomes, ServiceResponse must be nil.
	nonAck := []ConfirmResult{ConfirmResultError, ConfirmResultReject, ConfirmResultAbort}
	for _, r := range nonAck {
		t.Run(r.String(), func(t *testing.T) {
			ici := ConfirmICI{
				InvokeID:        InvokeID(9),
				Result:          r,
				ServiceResponse: nil,
			}
			if ici.ServiceResponse != nil {
				t.Errorf("ServiceResponse must be nil for %v", r)
			}
		})
	}
}

// --- String() fallback coverage ---

func TestNetworkPriorityStringFallback(t *testing.T) {
	got := netprim.NetworkPriority(0xFF).String()
	want := "network-priority(255)"
	if got != want {
		t.Errorf("String() = %q, want %q", got, want)
	}
}

func TestMaxSegmentsAcceptedStringFallback(t *testing.T) {
	got := MaxSegmentsAccepted(8).String()
	want := "8"
	if got != want {
		t.Errorf("String() = %q, want %q", got, want)
	}
}

func TestConfirmResultStringFallback(t *testing.T) {
	got := ConfirmResult(10).String()
	want := "confirm-result(10)"
	if got != want {
		t.Errorf("String() = %q, want %q", got, want)
	}
}
