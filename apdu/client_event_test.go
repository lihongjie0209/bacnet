package apdu

import (
	"bytes"
	"context"
	"reflect"
	"testing"
	"time"

	"github.com/worldiety/bacnet/common/netprim"
	"github.com/worldiety/bacnet/common/types"
	bacencoding "github.com/worldiety/bacnet/encoding"
	"github.com/worldiety/bacnet/npdu"
)

func TestEncodeAcknowledgeAlarmRequestGolden(t *testing.T) {
	object, _ := types.NewObjectIdentifier(types.ObjectTypeAnalogInput, 1)
	payload, err := encodeAcknowledgeAlarmRequest(AcknowledgeAlarmRequest{
		ProcessIdentifier: 7, EventObjectIdentifier: object,
		EventStateAcknowledged:   EventStateOffnormal,
		EventTimestamp:           Timestamp{Kind: TimestampSequence, Sequence: 9},
		AcknowledgementSource:    "op",
		AcknowledgementTimestamp: Timestamp{Kind: TimestampSequence, Sequence: 10},
	})
	if err != nil {
		t.Fatal(err)
	}
	want := []byte{
		0x09, 0x07,
		0x1c, 0x00, 0x00, 0x00, 0x01,
		0x29, 0x02,
		0x3e, 0x19, 0x09, 0x3f,
		0x4b, 0x00, 'o', 'p',
		0x5e, 0x19, 0x0a, 0x5f,
	}
	if !bytes.Equal(payload, want) {
		t.Fatalf("payload = %x, want %x", payload, want)
	}
}

func TestDecodeGetEventInformationACK(t *testing.T) {
	object, _ := types.NewObjectIdentifier(types.ObjectTypeAnalogInput, 3)
	payload := bacencoding.EncodeOpeningTag(0)
	payload = append(payload, bacencoding.EncodeContextPrimitive(0, bacencoding.EncodeObjectIdentifierValue(object))...)
	payload = append(payload, bacencoding.EncodeContextPrimitive(1, bacencoding.EncodeEnumeratedValue(uint32(EventStateOffnormal)))...)
	payload = append(payload, bacencoding.EncodeContextPrimitive(2, bacencoding.EncodeBitStringValue(bacencoding.NewBitString([]bool{true, false, true})))...)
	payload = append(payload, bacencoding.EncodeOpeningTag(3)...)
	for _, sequence := range []uint32{1, 2, 3} {
		payload = append(payload, bacencoding.EncodeContextPrimitive(1, bacencoding.EncodeUnsigned(sequence))...)
	}
	payload = append(payload, bacencoding.EncodeClosingTag(3)...)
	payload = append(payload, bacencoding.EncodeContextPrimitive(4, bacencoding.EncodeEnumeratedValue(1))...)
	payload = append(payload, bacencoding.EncodeContextPrimitive(5, bacencoding.EncodeBitStringValue(bacencoding.NewBitString([]bool{true, true, false})))...)
	payload = append(payload, bacencoding.EncodeOpeningTag(6)...)
	for _, priority := range []uint32{10, 20, 30} {
		payload = append(payload, bacencoding.EncodeApplicationPrimitive(uint8(bacencoding.AppTagUnsignedInteger), bacencoding.EncodeUnsigned(priority))...)
	}
	payload = append(payload, bacencoding.EncodeClosingTag(6)...)
	payload = append(payload, bacencoding.EncodeClosingTag(0)...)
	payload = append(payload, bacencoding.EncodeContextPrimitive(1, []byte{1})...)

	ack, err := decodeGetEventInformationACK(payload, 1)
	if err != nil {
		t.Fatal(err)
	}
	if !ack.MoreEvents || len(ack.Events) != 1 || ack.Events[0].ObjectIdentifier != object ||
		ack.Events[0].EventTimestamps[2].Sequence != 3 || ack.Events[0].EventPriorities != [3]uint32{10, 20, 30} {
		t.Fatalf("ack = %#v", ack)
	}
	if _, err := decodeGetEventInformationACK(append(payload, 0), 1); err == nil {
		t.Fatal("expected trailing-byte rejection")
	}
}

func TestGetEventInformationRequestGolden(t *testing.T) {
	object, _ := types.NewObjectIdentifier(types.ObjectTypeBinaryValue, 9)
	payload := bacencoding.EncodeContextPrimitive(0, bacencoding.EncodeObjectIdentifierValue(object))
	want := []byte{0x0c, 0x01, 0x40, 0x00, 0x09}
	if !bytes.Equal(payload, want) {
		t.Fatalf("payload = %x, want %x", payload, want)
	}
}

func TestAcknowledgeAlarmSimpleACK(t *testing.T) {
	transport := newTestNPDUTransport()
	ase, _ := NewASE(ASEConfig{InvokeTimeout: time.Second, MaxConcurrentInvokes: 4}, transport)
	clientRaw, err := NewClient(ase, ClientConfig{})
	if err != nil {
		t.Fatal(err)
	}
	client := clientRaw.(*clientImpl)
	dst, _ := netprim.NewAddress(netprim.LocalNetwork, []byte{1})
	object, _ := types.NewObjectIdentifier(types.ObjectTypeAnalogInput, 1)
	done := make(chan error, 1)
	go func() {
		done <- client.AcknowledgeAlarm(context.Background(), dst, AcknowledgeAlarmRequest{
			ProcessIdentifier: 7, EventObjectIdentifier: object,
			EventStateAcknowledged:   EventStateOffnormal,
			EventTimestamp:           Timestamp{Kind: TimestampSequence, Sequence: 9},
			AcknowledgementSource:    "operator",
			AcknowledgementTimestamp: Timestamp{Kind: TimestampSequence, Sequence: 10},
		})
	}()
	sent := <-transport.ch
	outbound, err := decodeAPDU(sent.packet.APDUBytes())
	if err != nil || outbound.ServiceChoice != ServiceChoiceAcknowledgeAlarm {
		t.Fatalf("outbound=%#v err=%v", outbound, err)
	}
	ack, _ := encodeAPDU(outboundAPDU{Type: PDUTypeSimpleACK, InvokeID: outbound.InvokeID, ServiceChoice: ServiceChoiceAcknowledgeAlarm})
	packet, _ := npdu.NewLocalAPDU(netprim.NetworkPriorityNormal, false, ack)
	if err := ase.OnInboundNPDU(context.Background(), dst, *packet); err != nil {
		t.Fatal(err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestAcknowledgeAlarmRejectsInvalidBeforeIO(t *testing.T) {
	object, _ := types.NewObjectIdentifier(types.ObjectTypeAnalogInput, 1)
	_, err := encodeAcknowledgeAlarmRequest(AcknowledgeAlarmRequest{
		EventObjectIdentifier: object, EventStateAcknowledged: EventState(99),
		AcknowledgementSource: "", EventTimestamp: Timestamp{Kind: TimestampKind(99)},
	})
	if err == nil {
		t.Fatal("expected validation error")
	}
}

func TestHandleEventNotificationsAndConfirmedACK(t *testing.T) {
	for _, confirmed := range []bool{false, true} {
		t.Run(map[bool]string{false: "unconfirmed", true: "confirmed"}[confirmed], func(t *testing.T) {
			transport := newTestNPDUTransport()
			ase, _ := NewASE(ASEConfig{InvokeTimeout: time.Second, MaxConcurrentInvokes: 4}, transport)
			clientRaw, err := NewClient(ase, ClientConfig{})
			if err != nil {
				t.Fatal(err)
			}
			client := clientRaw.(*clientImpl)
			received := make(chan EventNotificationIndication, 1)
			if confirmed {
				err = client.HandleConfirmedEventNotification(func(_ context.Context, event EventNotificationIndication) error {
					received <- event
					return nil
				})
			} else {
				err = client.HandleUnconfirmedEventNotification(func(_ context.Context, event EventNotificationIndication) error {
					received <- event
					return nil
				})
			}
			if err != nil {
				t.Fatal(err)
			}
			source, _ := netprim.NewAddress(netprim.LocalNetwork, []byte{2})
			pduType, choice := PDUTypeUnconfirmedRequest, ServiceChoiceUnconfirmedEventNotification
			invokeID := InvokeID(0)
			if confirmed {
				pduType, choice, invokeID = PDUTypeConfirmedRequest, ServiceChoiceConfirmedEventNotification, 19
			}
			encoded, err := encodeAPDU(outboundAPDU{Type: pduType, InvokeID: invokeID, ServiceChoice: choice, Payload: eventNotificationPayloadForTest(t, 0)})
			if err != nil {
				t.Fatal(err)
			}
			packet, _ := npdu.NewLocalAPDU(netprim.NetworkPriorityNormal, confirmed, encoded)
			if err := ase.OnInboundNPDU(context.Background(), source, *packet); err != nil {
				t.Fatal(err)
			}
			select {
			case event := <-received:
				if event.ProcessIdentifier != 7 || event.Priority != 99 || event.EventType != 0 || event.ToState != EventStateOffnormal ||
					event.MessageText == nil || *event.MessageText != "alarm" || !event.AckRequired || event.FromState == nil || len(event.RawParameters) == 0 || !event.Source.Equal(source) {
					t.Fatalf("event = %#v", event)
				}
			case <-time.After(time.Second):
				t.Fatal("timeout waiting for event notification")
			}
			if confirmed {
				sent := <-transport.ch
				ack, err := decodeAPDU(sent.packet.APDUBytes())
				if err != nil || ack.Type != PDUTypeSimpleACK || ack.InvokeID != invokeID || ack.ServiceChoice != choice {
					t.Fatalf("ack=%#v err=%v", ack, err)
				}
			}
		})
	}
}

func TestDecodeEventNotificationRejectsChoiceMismatchAndTrailingData(t *testing.T) {
	payload := eventNotificationPayloadForTest(t, 1)
	if _, err := decodeEventNotificationPayload(payload); err == nil {
		t.Fatal("expected event parameter choice mismatch")
	}
	payload = append(eventNotificationPayloadForTest(t, 0), 0)
	if _, err := decodeEventNotificationPayload(payload); err == nil {
		t.Fatal("expected trailing-byte rejection")
	}
}

func TestDecodeStandardEventParametersScalarChoices(t *testing.T) {
	status := bacencoding.EncodeBitStringValue(bacencoding.NewBitString([]bool{true, false, true, false}))
	bits := bacencoding.EncodeBitStringValue(bacencoding.NewBitString([]bool{true, false, true}))
	text, err := bacencoding.EncodeCharacterStringValue("alarm")
	if err != nil {
		t.Fatal(err)
	}
	alarmText, err := bacencoding.EncodeCharacterStringValue("high")
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name      string
		eventType uint32
		fields    []eventParameterField
		wantType  string
		want      map[string]any
	}{
		{
			name: "change of bitstring", eventType: 0, wantType: "change-of-bitstring",
			fields: []eventParameterField{{0, bits}, {1, status}},
			want:   map[string]any{"referencedBitString": []bool{true, false, true}, "statusFlags": []bool{true, false, true, false}},
		},
		{
			name: "floating limit", eventType: 4, wantType: "floating-limit",
			fields: []eventParameterField{{0, bacencoding.EncodeReal(1.25)}, {1, status}, {2, bacencoding.EncodeReal(2.5)}, {3, bacencoding.EncodeReal(0.5)}},
			want:   map[string]any{"referenceValue": float32(1.25), "statusFlags": []bool{true, false, true, false}, "setpointValue": float32(2.5), "errorLimit": float32(0.5)},
		},
		{
			name: "out of range", eventType: 5, wantType: "out-of-range",
			fields: []eventParameterField{{0, bacencoding.EncodeReal(9.5)}, {1, status}, {2, bacencoding.EncodeReal(1)}, {3, bacencoding.EncodeReal(8)}},
			want:   map[string]any{"exceedingValue": float32(9.5), "statusFlags": []bool{true, false, true, false}, "deadband": float32(1), "exceededLimit": float32(8)},
		},
		{
			name: "life safety", eventType: 8, wantType: "change-of-life-safety",
			fields: []eventParameterField{{0, bacencoding.EncodeEnumeratedValue(2)}, {1, bacencoding.EncodeEnumeratedValue(3)}, {2, status}, {3, bacencoding.EncodeEnumeratedValue(4)}},
			want:   map[string]any{"newState": uint32(2), "newMode": uint32(3), "statusFlags": []bool{true, false, true, false}, "operationExpected": uint32(4)},
		},
		{
			name: "unsigned range", eventType: 11, wantType: "unsigned-range",
			fields: []eventParameterField{{0, bacencoding.EncodeUnsigned(12)}, {1, status}, {2, bacencoding.EncodeUnsigned(10)}},
			want:   map[string]any{"exceedingValue": uint32(12), "statusFlags": []bool{true, false, true, false}, "exceededLimit": uint32(10)},
		},
		{
			name: "double out of range", eventType: 14, wantType: "double-out-of-range",
			fields: []eventParameterField{{0, bacencoding.EncodeDouble(12.5)}, {1, status}, {2, bacencoding.EncodeDouble(0.25)}, {3, bacencoding.EncodeDouble(10.5)}},
			want:   map[string]any{"exceedingValue": 12.5, "statusFlags": []bool{true, false, true, false}, "deadband": 0.25, "exceededLimit": 10.5},
		},
		{
			name: "signed out of range", eventType: 15, wantType: "signed-out-of-range",
			fields: []eventParameterField{{0, bacencoding.EncodeSigned(-12)}, {1, status}, {2, bacencoding.EncodeUnsigned(2)}, {3, bacencoding.EncodeSigned(-10)}},
			want:   map[string]any{"exceedingValue": int32(-12), "statusFlags": []bool{true, false, true, false}, "deadband": uint32(2), "exceededLimit": int32(-10)},
		},
		{
			name: "unsigned out of range", eventType: 16, wantType: "unsigned-out-of-range",
			fields: []eventParameterField{{0, bacencoding.EncodeUnsigned(12)}, {1, status}, {2, bacencoding.EncodeUnsigned(2)}, {3, bacencoding.EncodeUnsigned(10)}},
			want:   map[string]any{"exceedingValue": uint32(12), "statusFlags": []bool{true, false, true, false}, "deadband": uint32(2), "exceededLimit": uint32(10)},
		},
		{
			name: "character string", eventType: 17, wantType: "change-of-character-string",
			fields: []eventParameterField{{0, text}, {1, status}, {2, alarmText}},
			want:   map[string]any{"changedValue": "alarm", "statusFlags": []bool{true, false, true, false}, "alarmValue": "high"},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			parameterType, fields, err := decodeStandardEventParameters(test.eventType, encodeEventParameters(test.eventType, test.fields...))
			if err != nil {
				t.Fatal(err)
			}
			if parameterType != test.wantType || !reflect.DeepEqual(fields, test.want) {
				t.Fatalf("type=%q fields=%#v, want type=%q fields=%#v", parameterType, fields, test.wantType, test.want)
			}
		})
	}
}

func TestDecodeStandardEventParametersRejectsMalformedStandardChoice(t *testing.T) {
	badStatus := bacencoding.EncodeBitStringValue(bacencoding.NewBitString([]bool{true, false, true}))
	raw := encodeEventParameters(0,
		eventParameterField{0, bacencoding.EncodeBitStringValue(bacencoding.NewBitString([]bool{true}))},
		eventParameterField{1, badStatus},
	)
	if _, _, err := decodeStandardEventParameters(0, raw); err == nil {
		t.Fatal("expected invalid status-flags bit count rejection")
	}
	raw = encodeEventParameters(11,
		eventParameterField{0, bacencoding.EncodeUnsigned(2)},
		eventParameterField{1, bacencoding.EncodeBitStringValue(bacencoding.NewBitString([]bool{false, false, false, false}))},
		eventParameterField{2, bacencoding.EncodeUnsigned(1)},
		eventParameterField{3, bacencoding.EncodeUnsigned(99)},
	)
	if _, _, err := decodeStandardEventParameters(11, raw); err == nil {
		t.Fatal("expected trailing field rejection")
	}
}

func TestDecodeStandardEventParametersNestedAndApplicationChoices(t *testing.T) {
	status := bacencoding.EncodeBitStringValue(bacencoding.NewBitString([]bool{false, true, false, true}))
	appEnum, err := bacencoding.EncodeApplicationValue(bacencoding.AppEnum(2))
	if err != nil {
		t.Fatal(err)
	}
	appUnsigned, err := bacencoding.EncodeApplicationValue(bacencoding.AppUnsignedInteger(7))
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name      string
		eventType uint32
		body      []byte
		wantType  string
		want      map[string]any
	}{
		{
			name: "change of state", eventType: 1, wantType: "change-of-state",
			body: joinEventParameterBytes(
				bacencoding.EncodeOpeningTag(0),
				bacencoding.EncodeContextPrimitive(1, bacencoding.EncodeEnumeratedValue(2)),
				bacencoding.EncodeClosingTag(0),
				bacencoding.EncodeContextPrimitive(1, status),
			),
			want: map[string]any{
				"newState":    EventPropertyState{Choice: 1, Enumerated: uint32Pointer(2)},
				"statusFlags": []bool{false, true, false, true},
			},
		},
		{
			name: "change of value real", eventType: 2, wantType: "change-of-value",
			body: joinEventParameterBytes(
				bacencoding.EncodeOpeningTag(0),
				bacencoding.EncodeContextPrimitive(1, bacencoding.EncodeReal(3.5)),
				bacencoding.EncodeClosingTag(0),
				bacencoding.EncodeContextPrimitive(1, status),
			),
			want: map[string]any{"changedValue": EventChangeValue{Kind: "real", Real: float32Pointer(3.5)}, "statusFlags": []bool{false, true, false, true}},
		},
		{
			name: "command failure", eventType: 3, wantType: "command-failure",
			body: joinEventParameterBytes(
				bacencoding.EncodeOpeningTag(0), appEnum, bacencoding.EncodeClosingTag(0),
				bacencoding.EncodeContextPrimitive(1, status),
				bacencoding.EncodeOpeningTag(2), appEnum, bacencoding.EncodeClosingTag(2),
			),
			want: map[string]any{"commandValue": bacencoding.AppEnum(2), "statusFlags": []bool{false, true, false, true}, "feedbackValue": bacencoding.AppEnum(2)},
		},
		{
			name: "change of status flags", eventType: 18, wantType: "change-of-status-flags",
			body: joinEventParameterBytes(
				bacencoding.EncodeOpeningTag(0), appUnsigned, bacencoding.EncodeClosingTag(0),
				bacencoding.EncodeContextPrimitive(1, status),
			),
			want: map[string]any{"presentValue": bacencoding.AppUnsignedInteger(7), "referencedFlags": []bool{false, true, false, true}},
		},
		{
			name: "none", eventType: 20, wantType: "none", body: nil, want: map[string]any{},
		},
		{
			name: "change of discrete value", eventType: 21, wantType: "change-of-discrete-value",
			body: joinEventParameterBytes(
				bacencoding.EncodeOpeningTag(0), appUnsigned, bacencoding.EncodeClosingTag(0),
				bacencoding.EncodeContextPrimitive(1, status),
			),
			want: map[string]any{"newValue": bacencoding.AppUnsignedInteger(7), "statusFlags": []bool{false, true, false, true}},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			parameterType, fields, err := decodeStandardEventParameters(test.eventType, encodeEventParameterBody(test.eventType, test.body))
			if err != nil {
				t.Fatal(err)
			}
			if parameterType != test.wantType || !reflect.DeepEqual(fields, test.want) {
				t.Fatalf("type=%q fields=%#v, want type=%q fields=%#v", parameterType, fields, test.wantType, test.want)
			}
		})
	}
}

func uint32Pointer(value uint32) *uint32    { return &value }
func float32Pointer(value float32) *float32 { return &value }

func joinEventParameterBytes(parts ...[]byte) []byte {
	var out []byte
	for _, part := range parts {
		out = append(out, part...)
	}
	return out
}

func encodeEventParameterBody(eventType uint32, body []byte) []byte {
	return joinEventParameterBytes(bacencoding.EncodeOpeningTag(uint8(eventType)), body, bacencoding.EncodeClosingTag(uint8(eventType)))
}

type eventParameterField struct {
	tag   bacencoding.AppTag
	value []byte
}

func encodeEventParameters(eventType uint32, fields ...eventParameterField) []byte {
	encoded := bacencoding.EncodeOpeningTag(uint8(eventType))
	for _, field := range fields {
		encoded = append(encoded, bacencoding.EncodeContextPrimitive(uint8(field.tag), field.value)...)
	}
	return append(encoded, bacencoding.EncodeClosingTag(uint8(eventType))...)
}

func eventNotificationPayloadForTest(t *testing.T, parameterChoice uint8) []byte {
	t.Helper()
	device, _ := types.NewObjectIdentifier(types.ObjectTypeDevice, 123)
	object, _ := types.NewObjectIdentifier(types.ObjectTypeAnalogInput, 1)
	payload := bacencoding.EncodeContextPrimitive(0, bacencoding.EncodeUnsigned(7))
	payload = append(payload, bacencoding.EncodeContextPrimitive(1, bacencoding.EncodeObjectIdentifierValue(device))...)
	payload = append(payload, bacencoding.EncodeContextPrimitive(2, bacencoding.EncodeObjectIdentifierValue(object))...)
	timestamp, err := encodeContextTimestamp(3, Timestamp{Kind: TimestampSequence, Sequence: 11})
	if err != nil {
		t.Fatal(err)
	}
	payload = append(payload, timestamp...)
	payload = append(payload, bacencoding.EncodeContextPrimitive(4, bacencoding.EncodeUnsigned(4))...)
	payload = append(payload, bacencoding.EncodeContextPrimitive(5, bacencoding.EncodeUnsigned(99))...)
	payload = append(payload, bacencoding.EncodeContextPrimitive(6, bacencoding.EncodeEnumeratedValue(0))...)
	message, _ := bacencoding.EncodeCharacterStringValue("alarm")
	payload = append(payload, bacencoding.EncodeContextPrimitive(7, message)...)
	payload = append(payload, bacencoding.EncodeContextPrimitive(8, bacencoding.EncodeEnumeratedValue(0))...)
	payload = append(payload, bacencoding.EncodeContextPrimitive(9, []byte{1})...)
	payload = append(payload, bacencoding.EncodeContextPrimitive(10, bacencoding.EncodeEnumeratedValue(uint32(EventStateNormal)))...)
	payload = append(payload, bacencoding.EncodeContextPrimitive(11, bacencoding.EncodeEnumeratedValue(uint32(EventStateOffnormal)))...)
	payload = append(payload, bacencoding.EncodeOpeningTag(12)...)
	payload = append(payload, bacencoding.EncodeOpeningTag(parameterChoice)...)
	payload = append(payload, bacencoding.EncodeContextPrimitive(0, bacencoding.EncodeBitStringValue(bacencoding.NewBitString([]bool{true})))...)
	payload = append(payload, bacencoding.EncodeContextPrimitive(1, bacencoding.EncodeBitStringValue(bacencoding.NewBitString([]bool{false, false, false, false})))...)
	payload = append(payload, bacencoding.EncodeClosingTag(parameterChoice)...)
	payload = append(payload, bacencoding.EncodeClosingTag(12)...)
	return payload
}
