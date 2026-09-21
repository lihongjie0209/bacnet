package apdu

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/worldiety/bacnet/common/netprim"
	"github.com/worldiety/bacnet/common/types"
	"github.com/worldiety/bacnet/npdu"
)

func TestSubscribeCOVAndSubscribeCOVPropertySimpleACK(t *testing.T) {
	tests := []struct {
		name          string
		serviceChoice ServiceChoice
		invoke        func(*clientImpl, context.Context, netprim.Address) error
	}{
		{
			name:          "subscribe-cov",
			serviceChoice: ServiceChoiceSubscribeCOV,
			invoke: func(c *clientImpl, ctx context.Context, dst netprim.Address) error {
				objID, _ := types.NewObjectIdentifier(types.ObjectTypeAnalogInput, 7)
				issueConfirmed := true
				lifetime := COVLifetime(120)
				req := SubscribeCOVRequest{
					SubscriberProcessIdentifier: 1,
					MonitoredObjectIdentifier:   objID,
					IssueConfirmedNotifications: &issueConfirmed,
					Lifetime:                    &lifetime,
				}
				return c.SubscribeCOV(ctx, dst, req)
			},
		},
		{
			name:          "subscribe-cov-property",
			serviceChoice: ServiceChoiceSubscribeCOVProperty,
			invoke: func(c *clientImpl, ctx context.Context, dst netprim.Address) error {
				objID, _ := types.NewObjectIdentifier(types.ObjectTypeAnalogInput, 7)
				issueConfirmed := false
				lifetime := COVLifetime(30)
				increment := COVIncrement(0.5)
				req := SubscribeCOVPropertyRequest{
					SubscriberProcessIdentifier: 9,
					MonitoredObjectIdentifier:   objID,
					IssueConfirmedNotifications: &issueConfirmed,
					Lifetime:                    &lifetime,
					MonitoredProperty: MonitoredPropertyReference{
						PropertyIdentifier: types.PropertyIdentifierPresentValue,
					},
					COVIncrement: &increment,
				}
				return c.SubscribeCOVProperty(ctx, dst, req)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			transport := newTestNPDUTransport()
			ase, _ := NewASE(ASEConfig{InvokeTimeout: time.Second, MaxConcurrentInvokes: 4}, transport)
			clientRaw, err := NewClient(ase, ClientConfig{})
			if err != nil {
				t.Fatalf("NewClient: %v", err)
			}
			client := clientRaw.(*clientImpl)
			dst, _ := netprim.NewAddress(netprim.LocalNetwork, []byte{0x01})

			ch := make(chan error, 1)
			go func() { ch <- tt.invoke(client, context.Background(), dst) }()

			sent := <-transport.ch
			outbound, err := decodeAPDU(sent.packet.APDUBytes())
			if err != nil {
				t.Fatalf("decodeAPDU: %v", err)
			}
			if outbound.Type != PDUTypeConfirmedRequest {
				t.Fatalf("type = %v, want %v", outbound.Type, PDUTypeConfirmedRequest)
			}
			if outbound.ServiceChoice != tt.serviceChoice {
				t.Fatalf("service = %v, want %v", outbound.ServiceChoice, tt.serviceChoice)
			}

			ackBytes, err := encodeAPDU(outboundAPDU{Type: PDUTypeSimpleACK, InvokeID: outbound.InvokeID, ServiceChoice: tt.serviceChoice})
			if err != nil {
				t.Fatalf("encodeAPDU: %v", err)
			}
			ackNPDU, _ := npdu.NewLocalAPDU(netprim.NetworkPriorityNormal, false, ackBytes)
			if err := ase.OnInboundNPDU(context.Background(), dst, *ackNPDU); err != nil {
				t.Fatalf("OnInboundNPDU: %v", err)
			}

			if err := <-ch; err != nil {
				t.Fatalf("call error: %v", err)
			}
		})
	}
}

func TestSubscribeCOVPhaseRemoteErrorMapping(t *testing.T) {
	tests := []struct {
		name      string
		pduType   PDUType
		wantIsErr error
	}{
		{name: "error", pduType: PDUTypeError, wantIsErr: ErrRemoteError},
		{name: "reject", pduType: PDUTypeReject, wantIsErr: ErrRemoteReject},
		{name: "abort", pduType: PDUTypeAbort, wantIsErr: ErrRemoteAbort},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			transport := newTestNPDUTransport()
			ase, _ := NewASE(ASEConfig{InvokeTimeout: time.Second, MaxConcurrentInvokes: 4}, transport)
			clientRaw, err := NewClient(ase, ClientConfig{})
			if err != nil {
				t.Fatalf("NewClient: %v", err)
			}
			client := clientRaw.(*clientImpl)
			dst, _ := netprim.NewAddress(netprim.LocalNetwork, []byte{0x01})
			objID, _ := types.NewObjectIdentifier(types.ObjectTypeAnalogInput, 7)
			req := SubscribeCOVRequest{SubscriberProcessIdentifier: 1, MonitoredObjectIdentifier: objID}

			ch := make(chan error, 1)
			go func() { ch <- client.SubscribeCOV(context.Background(), dst, req) }()

			sent := <-transport.ch
			outbound, err := decodeAPDU(sent.packet.APDUBytes())
			if err != nil {
				t.Fatalf("decodeAPDU: %v", err)
			}

			payload := []byte{0x01}
			if tt.pduType == PDUTypeError {
				payload = []byte{0x01, 0x02}
			}
			inboundBytes, err := encodeAPDU(outboundAPDU{Type: tt.pduType, InvokeID: outbound.InvokeID, ServiceChoice: ServiceChoiceSubscribeCOV, Payload: payload})
			if err != nil {
				t.Fatalf("encodeAPDU: %v", err)
			}
			inbound, _ := npdu.NewLocalAPDU(netprim.NetworkPriorityNormal, false, inboundBytes)
			if err := ase.OnInboundNPDU(context.Background(), dst, *inbound); err != nil {
				t.Fatalf("OnInboundNPDU: %v", err)
			}

			err = <-ch
			if !errors.Is(err, tt.wantIsErr) {
				t.Fatalf("err = %v, want errors.Is(_, %v)", err, tt.wantIsErr)
			}
		})
	}
}

func TestHandleUnconfirmedCOVNotification(t *testing.T) {
	transport := newTestNPDUTransport()
	ase, _ := NewASE(ASEConfig{InvokeTimeout: time.Second, MaxConcurrentInvokes: 4}, transport)
	clientRaw, err := NewClient(ase, ClientConfig{})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	client := clientRaw.(*clientImpl)

	indicationCh := make(chan UnconfirmedCOVNotificationIndication, 1)
	err = client.HandleUnconfirmedCOVNotification(func(_ context.Context, indication UnconfirmedCOVNotificationIndication) error {
		indicationCh <- indication
		return nil
	})
	if err != nil {
		t.Fatalf("HandleUnconfirmedCOVNotification: %v", err)
	}

	src, _ := netprim.NewAddress(netprim.LocalNetwork, []byte{0x02})
	devID, _ := types.NewObjectIdentifier(types.ObjectTypeDevice, 1234)
	objID, _ := types.NewObjectIdentifier(types.ObjectTypeAnalogInput, 7)
	payload := encodeUnconfirmedCOVNotificationPayloadForTest(1, devID, objID, 60, []COVPropertyValue{{
		PropertyIdentifier: types.PropertyIdentifierPresentValue,
		Value:              []byte{0x44, 0x41, 0x20, 0x00, 0x00},
	}})

	apduBytes, err := encodeAPDU(outboundAPDU{Type: PDUTypeUnconfirmedRequest, ServiceChoice: ServiceChoiceUnconfirmedCOVNotification, Payload: payload})
	if err != nil {
		t.Fatalf("encodeAPDU: %v", err)
	}
	npkt, err := npdu.NewLocalAPDU(netprim.NetworkPriorityNormal, false, apduBytes)
	if err != nil {
		t.Fatalf("NewLocalAPDU: %v", err)
	}
	if err := ase.OnInboundNPDU(context.Background(), src, *npkt); err != nil {
		t.Fatalf("OnInboundNPDU: %v", err)
	}

	select {
	case got := <-indicationCh:
		if !got.Source.Equal(src) {
			t.Fatalf("source = %v, want %v", got.Source, src)
		}
		if got.InitiatingDeviceIdentifier != devID {
			t.Fatalf("initiating device = %v, want %v", got.InitiatingDeviceIdentifier, devID)
		}
		if got.MonitoredObjectIdentifier != objID {
			t.Fatalf("monitored object = %v, want %v", got.MonitoredObjectIdentifier, objID)
		}
		if len(got.Values) != 1 {
			t.Fatalf("values len = %d, want 1", len(got.Values))
		}
	case <-time.After(time.Second):
		t.Fatalf("timeout waiting for COV notification handler call")
	}
}

func TestHandleConfirmedCOVNotificationAcknowledgesAfterHandler(t *testing.T) {
	transport := newTestNPDUTransport()
	ase, _ := NewASE(ASEConfig{InvokeTimeout: time.Second, MaxConcurrentInvokes: 4}, transport)
	clientRaw, err := NewClient(ase, ClientConfig{})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	client := clientRaw.(*clientImpl)

	handled := make(chan ConfirmedCOVNotificationIndication, 1)
	if err = client.HandleConfirmedCOVNotification(func(_ context.Context, indication ConfirmedCOVNotificationIndication) error {
		handled <- indication
		return nil
	}); err != nil {
		t.Fatalf("HandleConfirmedCOVNotification: %v", err)
	}

	src, _ := netprim.NewAddress(netprim.LocalNetwork, []byte{0x02})
	devID, _ := types.NewObjectIdentifier(types.ObjectTypeDevice, 1234)
	objID, _ := types.NewObjectIdentifier(types.ObjectTypeAnalogInput, 7)
	payload := encodeUnconfirmedCOVNotificationPayloadForTest(3, devID, objID, 60, []COVPropertyValue{{
		PropertyIdentifier: types.PropertyIdentifierPresentValue,
		Value:              []byte{0x44, 0x41, 0x20, 0x00, 0x00},
	}})
	apduBytes, err := encodeAPDU(outboundAPDU{Type: PDUTypeConfirmedRequest, InvokeID: 19, ServiceChoice: ServiceChoiceConfirmedCOVNotification, Payload: payload})
	if err != nil {
		t.Fatalf("encodeAPDU: %v", err)
	}
	npkt, _ := npdu.NewLocalAPDU(netprim.NetworkPriorityNormal, true, apduBytes)
	if err = ase.OnInboundNPDU(context.Background(), src, *npkt); err != nil {
		t.Fatalf("OnInboundNPDU: %v", err)
	}

	select {
	case got := <-handled:
		if got.SubscriberProcessIdentifier != 3 || !got.Source.Equal(src) {
			t.Fatalf("indication = %#v", got)
		}
	case <-time.After(time.Second):
		t.Fatal("timeout waiting for confirmed COV handler")
	}
	sent := <-transport.ch
	ack, err := decodeAPDU(sent.packet.APDUBytes())
	if err != nil {
		t.Fatalf("decode ack: %v", err)
	}
	if ack.Type != PDUTypeSimpleACK || ack.InvokeID != 19 || ack.ServiceChoice != ServiceChoiceConfirmedCOVNotification {
		t.Fatalf("ack = %#v", ack)
	}
}

func TestHandleUnconfirmedCOVNotificationMultiple(t *testing.T) {
	transport := newTestNPDUTransport()
	ase, _ := NewASE(ASEConfig{InvokeTimeout: time.Second, MaxConcurrentInvokes: 4}, transport)
	clientRaw, err := NewClient(ase, ClientConfig{})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	client := clientRaw.(*clientImpl)

	indicationCh := make(chan UnconfirmedCOVNotificationMultipleIndication, 1)
	err = client.HandleUnconfirmedCOVNotificationMultiple(func(_ context.Context, indication UnconfirmedCOVNotificationMultipleIndication) error {
		indicationCh <- indication
		return nil
	})
	if err != nil {
		t.Fatalf("HandleUnconfirmedCOVNotificationMultiple: %v", err)
	}

	src, _ := netprim.NewAddress(netprim.LocalNetwork, []byte{0x02})
	devID, _ := types.NewObjectIdentifier(types.ObjectTypeDevice, 1234)
	objID, _ := types.NewObjectIdentifier(types.ObjectTypeAnalogInput, 7)
	payload := encodeUnconfirmedCOVNotificationMultiplePayloadForTest(1, devID, 90, []COVNotificationMultipleObject{{
		ObjectIdentifier: objID,
		Values: []COVPropertyValue{{
			PropertyIdentifier: types.PropertyIdentifierPresentValue,
			Value:              []byte{0x44, 0x41, 0x20, 0x00, 0x00},
		}},
	}})
	decodedPayload, err := decodeUnconfirmedCOVNotificationMultiplePayload(payload)
	if err != nil {
		t.Fatalf("direct decode failed: %v payload=%v", err, payload)
	}
	if len(decodedPayload.Objects) != 1 {
		t.Fatalf("decoded payload objects len = %d, want 1", len(decodedPayload.Objects))
	}

	apduBytes, err := encodeAPDU(outboundAPDU{Type: PDUTypeUnconfirmedRequest, ServiceChoice: ServiceChoiceUnconfirmedCOVNotificationMultiple, Payload: payload})
	if err != nil {
		t.Fatalf("encodeAPDU: %v", err)
	}
	npkt, err := npdu.NewLocalAPDU(netprim.NetworkPriorityNormal, false, apduBytes)
	if err != nil {
		t.Fatalf("NewLocalAPDU: %v", err)
	}
	if err := ase.OnInboundNPDU(context.Background(), src, *npkt); err != nil {
		t.Fatalf("OnInboundNPDU: %v", err)
	}

	select {
	case got := <-indicationCh:
		if !got.Source.Equal(src) {
			t.Fatalf("source = %v, want %v", got.Source, src)
		}
		if got.InitiatingDeviceIdentifier != devID {
			t.Fatalf("initiating device = %v, want %v", got.InitiatingDeviceIdentifier, devID)
		}
		if len(got.Objects) != 1 || got.Objects[0].ObjectIdentifier != objID {
			t.Fatalf("objects = %#v", got.Objects)
		}
	case <-time.After(time.Second):
		t.Fatalf("timeout waiting for multiple COV notification handler call")
	}
}

func TestHandleUnconfirmedCOVNilHandlersAndMalformedPayloads(t *testing.T) {
	transport := newTestNPDUTransport()
	ase, _ := NewASE(ASEConfig{InvokeTimeout: time.Second, MaxConcurrentInvokes: 4}, transport)
	clientRaw, err := NewClient(ase, ClientConfig{})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	client := clientRaw.(*clientImpl)

	if err := client.HandleUnconfirmedCOVNotification(nil); !errors.Is(err, ErrHandlerNotFound) {
		t.Fatalf("HandleUnconfirmedCOVNotification nil err = %v, want %v", err, ErrHandlerNotFound)
	}
	if err := client.HandleConfirmedCOVNotification(nil); !errors.Is(err, ErrHandlerNotFound) {
		t.Fatalf("HandleConfirmedCOVNotification nil err = %v, want %v", err, ErrHandlerNotFound)
	}
	if err := client.HandleUnconfirmedCOVNotificationMultiple(nil); !errors.Is(err, ErrHandlerNotFound) {
		t.Fatalf("HandleUnconfirmedCOVNotificationMultiple nil err = %v, want %v", err, ErrHandlerNotFound)
	}

	if err := client.HandleUnconfirmedCOVNotification(func(_ context.Context, _ UnconfirmedCOVNotificationIndication) error { return nil }); err != nil {
		t.Fatalf("HandleUnconfirmedCOVNotification: %v", err)
	}
	if err := client.HandleUnconfirmedCOVNotificationMultiple(func(_ context.Context, _ UnconfirmedCOVNotificationMultipleIndication) error { return nil }); err != nil {
		t.Fatalf("HandleUnconfirmedCOVNotificationMultiple: %v", err)
	}

	src, _ := netprim.NewAddress(netprim.LocalNetwork, []byte{0x02})
	badPayloads := []struct {
		name    string
		service ServiceChoice
		payload []byte
	}{
		{name: "single malformed", service: ServiceChoiceUnconfirmedCOVNotification, payload: []byte{0x00}},
		{name: "multiple malformed", service: ServiceChoiceUnconfirmedCOVNotificationMultiple, payload: []byte{0x00}},
	}
	for _, tt := range badPayloads {
		t.Run(tt.name, func(t *testing.T) {
			apduBytes, err := encodeAPDU(outboundAPDU{Type: PDUTypeUnconfirmedRequest, ServiceChoice: tt.service, Payload: tt.payload})
			if err != nil {
				t.Fatalf("encodeAPDU: %v", err)
			}
			npkt, err := npdu.NewLocalAPDU(netprim.NetworkPriorityNormal, false, apduBytes)
			if err != nil {
				t.Fatalf("NewLocalAPDU: %v", err)
			}
			err = ase.OnInboundNPDU(context.Background(), src, *npkt)
			if !errors.Is(err, ErrDecodeFailure) {
				t.Fatalf("err = %v, want %v", err, ErrDecodeFailure)
			}
		})
	}
}

func encodeUnconfirmedCOVNotificationPayloadForTest(
	processID SubscriberProcessIdentifier,
	initiatingDeviceIdentifier types.ObjectIdentifier,
	monitoredObjectIdentifier types.ObjectIdentifier,
	timeRemaining COVLifetime,
	values []COVPropertyValue,
) []byte {
	out := make([]byte, 0, 64)
	out = append(out, encodeContextPrimitive(0, encodeUnsigned(uint32(processID)))...)
	rawInitiating := uint32(initiatingDeviceIdentifier)
	out = append(out, encodeContextPrimitive(1, []byte{byte(rawInitiating >> 24), byte(rawInitiating >> 16), byte(rawInitiating >> 8), byte(rawInitiating)})...)
	rawMonitored := uint32(monitoredObjectIdentifier)
	out = append(out, encodeContextPrimitive(2, []byte{byte(rawMonitored >> 24), byte(rawMonitored >> 16), byte(rawMonitored >> 8), byte(rawMonitored)})...)
	out = append(out, encodeContextPrimitive(3, encodeUnsigned(uint32(timeRemaining)))...)
	out = append(out, encodeOpeningTag(4)...)
	for _, v := range values {
		out = append(out, encodeContextPrimitive(0, encodeUnsigned(uint32(v.PropertyIdentifier)))...)
		if v.ArrayIndex != nil {
			out = append(out, encodeContextPrimitive(1, encodeUnsigned(*v.ArrayIndex))...)
		}
		out = append(out, encodeOpeningTag(2)...)
		out = append(out, v.Value...)
		out = append(out, encodeClosingTag(2)...)
		if v.Priority != nil {
			out = append(out, encodeContextPrimitive(3, encodeUnsigned(uint32(*v.Priority)))...)
		}
	}
	out = append(out, encodeClosingTag(4)...)
	return out
}

func encodeUnconfirmedCOVNotificationMultiplePayloadForTest(
	processID SubscriberProcessIdentifier,
	initiatingDeviceIdentifier types.ObjectIdentifier,
	timeRemaining COVLifetime,
	objects []COVNotificationMultipleObject,
) []byte {
	out := make([]byte, 0, 96)
	out = append(out, encodeContextPrimitive(0, encodeUnsigned(uint32(processID)))...)
	rawInitiating := uint32(initiatingDeviceIdentifier)
	out = append(out, encodeContextPrimitive(1, []byte{byte(rawInitiating >> 24), byte(rawInitiating >> 16), byte(rawInitiating >> 8), byte(rawInitiating)})...)
	out = append(out, encodeContextPrimitive(2, encodeUnsigned(uint32(timeRemaining)))...)
	out = append(out, encodeOpeningTag(3)...)
	for _, obj := range objects {
		rawObj := uint32(obj.ObjectIdentifier)
		out = append(out, encodeContextPrimitive(0, []byte{byte(rawObj >> 24), byte(rawObj >> 16), byte(rawObj >> 8), byte(rawObj)})...)
		out = append(out, encodeOpeningTag(1)...)
		for _, v := range obj.Values {
			out = append(out, encodeContextPrimitive(0, encodeUnsigned(uint32(v.PropertyIdentifier)))...)
			if v.ArrayIndex != nil {
				out = append(out, encodeContextPrimitive(1, encodeUnsigned(*v.ArrayIndex))...)
			}
			out = append(out, encodeOpeningTag(2)...)
			out = append(out, v.Value...)
			out = append(out, encodeClosingTag(2)...)
			if v.Priority != nil {
				out = append(out, encodeContextPrimitive(3, encodeUnsigned(uint32(*v.Priority)))...)
			}
		}
		out = append(out, encodeClosingTag(1)...)
	}
	out = append(out, encodeClosingTag(3)...)
	return out
}
