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

func TestClientReadPropertyMultiple(t *testing.T) {
	transport := newTestNPDUTransport()
	ase, _ := NewASE(ASEConfig{InvokeTimeout: time.Second, MaxConcurrentInvokes: 4}, transport)
	clientRaw, err := NewClient(ase, ClientConfig{})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	client := clientRaw.(*clientImpl)

	dst, _ := netprim.NewAddress(netprim.LocalNetwork, []byte{0x01})
	objID, _ := types.NewObjectIdentifier(types.ObjectTypeAnalogInput, 7)
	arrayIndex := uint32(2)
	req := ReadPropertyMultipleRequest{
		Specs: []ReadAccessSpecification{{
			ObjectIdentifier: objID,
			Properties: []PropertyReference{
				{PropertyIdentifier: types.PropertyIdentifierPresentValue},
				{PropertyIdentifier: types.PropertyIdentifierStatusFlags, ArrayIndex: &arrayIndex},
			},
		}},
	}

	type result struct {
		ack ReadPropertyMultipleACK
		err error
	}
	ch := make(chan result, 1)
	go func() {
		ack, callErr := client.ReadPropertyMultiple(context.Background(), dst, req)
		ch <- result{ack: ack, err: callErr}
	}()

	sent := <-transport.ch
	outbound, err := decodeAPDU(sent.packet.APDUBytes())
	if err != nil {
		t.Fatalf("decodeAPDU: %v", err)
	}

	if outbound.Type != PDUTypeConfirmedRequest {
		t.Fatalf("type = %v, want %v", outbound.Type, PDUTypeConfirmedRequest)
	}

	if outbound.ServiceChoice != ServiceChoiceReadPropertyMultiple {
		t.Fatalf("service = %v, want %v", outbound.ServiceChoice, ServiceChoiceReadPropertyMultiple)
	}

	decodedReq, err := decodeReadPropertyMultipleRequestPayloadForTest(outbound.Payload)
	if err != nil {
		t.Fatalf("decodeReadPropertyMultipleRequestPayloadForTest: %v", err)
	}

	if len(decodedReq.Specs) != 1 || len(decodedReq.Specs[0].Properties) != 2 {
		t.Fatalf("decoded specs = %#v", decodedReq.Specs)
	}

	ackPayload := encodeReadPropertyMultipleACKPayloadForTest(ReadPropertyMultipleACK{
		Results: []ReadAccessResult{{
			ObjectIdentifier: objID,
			Results: []ReadPropertyResult{{
				PropertyIdentifier: types.PropertyIdentifierPresentValue,
				PropertyValue:      []byte{0x44, 0x41, 0x20, 0x00, 0x00},
			}},
		}},
	})
	ackBytes, err := encodeAPDU(outboundAPDU{
		Type:          PDUTypeComplexACK,
		InvokeID:      outbound.InvokeID,
		ServiceChoice: ServiceChoiceReadPropertyMultiple,
		Payload:       ackPayload,
	})
	if err != nil {
		t.Fatalf("encodeAPDU: %v", err)
	}
	ackNPDU, _ := npdu.NewLocalAPDU(netprim.NetworkPriorityNormal, false, ackBytes)
	if err := ase.OnInboundNPDU(context.Background(), dst, *ackNPDU); err != nil {
		t.Fatalf("OnInboundNPDU: %v", err)
	}

	res := <-ch
	if res.err != nil {
		t.Fatalf("ReadPropertyMultiple: %v", res.err)
	}

	if len(res.ack.Results) != 1 {
		t.Fatalf("results len = %d, want 1", len(res.ack.Results))
	}

	if len(res.ack.Results[0].Results) != 1 {
		t.Fatalf("property results len = %d, want 1", len(res.ack.Results[0].Results))
	}
}

func TestReadPropertyResultDecodeError(t *testing.T) {
	// A BACnet-Error body: two application-tag-9 enumerateds (class, code).
	// class=property(2), code=unknown-property(32). Application tag 9, length 1:
	// 0x91 <value>.
	errBody := []byte{
		0x91, byte(ErrorClassProperty), // error-class = property (2)
		0x91, byte(ErrorCodePropertyUnknownProperty), // error-code = unknown-property (32)
	}

	r := ReadPropertyResult{
		PropertyIdentifier: types.PropertyIdentifierPresentValue,
		Error:              errBody,
	}
	class, code, err := r.DecodeError()
	if err != nil {
		t.Fatalf("DecodeError: %v", err)
	}
	if class != ErrorClassProperty {
		t.Errorf("class = %v, want %v", class, ErrorClassProperty)
	}
	if code != ErrorCodePropertyUnknownProperty {
		t.Errorf("code = %v, want %v", code, ErrorCodePropertyUnknownProperty)
	}

	// Empty error -> decode failure.
	if _, _, err := (ReadPropertyResult{}).DecodeError(); err == nil {
		t.Fatal("DecodeError on empty result: want error, got nil")
	} else if !errors.Is(err, ErrDecodeFailure) {
		t.Errorf("error should wrap ErrDecodeFailure, got %v", err)
	}

	// Malformed error body -> decode failure.
	if _, _, err := (ReadPropertyResult{Error: []byte{0x21, 0x05}}).DecodeError(); err == nil {
		t.Fatal("DecodeError on malformed body: want error, got nil")
	}
}

func TestClientWritePropertyAndWritePropertyMultipleSimpleACK(t *testing.T) {
	tests := []struct {
		name    string
		service ServiceChoice
		invoke  func(*clientImpl, context.Context, netprim.Address) error
	}{
		{
			name:    "write-property",
			service: ServiceChoiceWriteProperty,
			invoke: func(c *clientImpl, ctx context.Context, dst netprim.Address) error {
				objID, _ := types.NewObjectIdentifier(types.ObjectTypeAnalogValue, 1)
				req := WritePropertyRequest{
					ObjectIdentifier:   objID,
					PropertyIdentifier: types.PropertyIdentifierPresentValue,
					PropertyValue:      []byte{0x44, 0x48, 0x00, 0x00},
				}
				return c.WriteProperty(ctx, dst, req)
			},
		},
		{
			name:    "write-property-multiple",
			service: ServiceChoiceWritePropertyMultiple,
			invoke: func(c *clientImpl, ctx context.Context, dst netprim.Address) error {
				objID, _ := types.NewObjectIdentifier(types.ObjectTypeAnalogValue, 1)
				req := WritePropertyMultipleRequest{Writes: []WriteAccessSpecification{{
					ObjectIdentifier: objID,
					Values: []PropertyValueWrite{{
						PropertyIdentifier: types.PropertyIdentifierPresentValue,
						PropertyValue:      []byte{0x44, 0x48, 0x00, 0x00},
					}},
				}}}
				return c.WritePropertyMultiple(ctx, dst, req)
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
			if outbound.ServiceChoice != tt.service {
				t.Fatalf("service = %v, want %v", outbound.ServiceChoice, tt.service)
			}

			ackBytes, err := encodeAPDU(outboundAPDU{Type: PDUTypeSimpleACK, InvokeID: outbound.InvokeID, ServiceChoice: tt.service})
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

func TestPhase2RemoteErrorMapping(t *testing.T) {
	tests := []struct {
		name      string
		pduType   PDUType
		wantIsErr error
		wantType  any
	}{
		{name: "error", pduType: PDUTypeError, wantIsErr: ErrRemoteError, wantType: RemoteErrorAPDU{}},
		{name: "reject", pduType: PDUTypeReject, wantIsErr: ErrRemoteReject, wantType: RemoteRejectAPDU{}},
		{name: "abort", pduType: PDUTypeAbort, wantIsErr: ErrRemoteAbort, wantType: RemoteAbortAPDU{}},
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

			objID, _ := types.NewObjectIdentifier(types.ObjectTypeAnalogValue, 1)
			req := WritePropertyRequest{
				ObjectIdentifier:   objID,
				PropertyIdentifier: types.PropertyIdentifierPresentValue,
				PropertyValue:      []byte{0x44, 0x00, 0x00, 0x00},
			}

			ch := make(chan error, 1)
			go func() { ch <- client.WriteProperty(context.Background(), dst, req) }()

			sent := <-transport.ch
			outbound, err := decodeAPDU(sent.packet.APDUBytes())
			if err != nil {
				t.Fatalf("decodeAPDU: %v", err)
			}

			payload := []byte{0x01}
			if tt.pduType == PDUTypeError {
				payload = []byte{0x01, 0x02}
			}
			inboundBytes, err := encodeAPDU(outboundAPDU{Type: tt.pduType, InvokeID: outbound.InvokeID, ServiceChoice: ServiceChoiceWriteProperty, Payload: payload})
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
			switch tt.wantType.(type) {
			case RemoteErrorAPDU:
				if _, ok := asType[RemoteErrorAPDU](err); !ok {
					t.Fatalf("expected RemoteErrorAPDU, got %v", err)
				}
			case RemoteRejectAPDU:
				if _, ok := asType[RemoteRejectAPDU](err); !ok {
					t.Fatalf("expected RemoteRejectAPDU, got %v", err)
				}
			case RemoteAbortAPDU:
				if _, ok := asType[RemoteAbortAPDU](err); !ok {
					t.Fatalf("expected RemoteAbortAPDU, got %v", err)
				}
			}
		})
	}
}

func decodeReadPropertyMultipleRequestPayloadForTest(payload []byte) (ReadPropertyMultipleRequest, error) {
	cursor := 0
	res := ReadPropertyMultipleRequest{Specs: make([]ReadAccessSpecification, 0)}

	for cursor < len(payload) {
		_, objBytes, next, err := decodeExpectedContextPrimitive(payload, cursor, 0)
		if err != nil {
			return ReadPropertyMultipleRequest{}, err
		}
		if len(objBytes) != 4 {
			return ReadPropertyMultipleRequest{}, errors.New("invalid object identifier length")
		}
		objID := types.ObjectIdentifier(uint32(objBytes[0])<<24 | uint32(objBytes[1])<<16 | uint32(objBytes[2])<<8 | uint32(objBytes[3]))
		cursor = next

		next, err = expectOpeningTag(payload, cursor, 1)
		if err != nil {
			return ReadPropertyMultipleRequest{}, err
		}
		cursor = next

		spec := ReadAccessSpecification{ObjectIdentifier: objID, Properties: make([]PropertyReference, 0)}
		for {
			if isClosingTagAt(payload, cursor, 1) {
				cursor++
				break
			}
			_, propBytes, next, err := decodeExpectedContextPrimitive(payload, cursor, 0)
			if err != nil {
				return ReadPropertyMultipleRequest{}, err
			}
			propID, err := decodeUnsigned(propBytes)
			if err != nil {
				return ReadPropertyMultipleRequest{}, err
			}
			cursor = next

			pref := PropertyReference{PropertyIdentifier: types.PropertyIdentifier(propID)}
			if cursor < len(payload) && looksLikeContextPrimitiveTag(payload[cursor], 1) {
				_, idxBytes, next, err := decodeExpectedContextPrimitive(payload, cursor, 1)
				if err != nil {
					return ReadPropertyMultipleRequest{}, err
				}
				idx, err := decodeUnsigned(idxBytes)
				if err != nil {
					return ReadPropertyMultipleRequest{}, err
				}
				pref.ArrayIndex = &idx
				cursor = next
			}
			spec.Properties = append(spec.Properties, pref)
		}

		res.Specs = append(res.Specs, spec)
	}

	return res, nil
}

func encodeReadPropertyMultipleACKPayloadForTest(ack ReadPropertyMultipleACK) []byte {
	out := make([]byte, 0, 64)
	for _, objResult := range ack.Results {
		rawObj := uint32(objResult.ObjectIdentifier)
		out = append(out, encodeContextPrimitive(0, []byte{byte(rawObj >> 24), byte(rawObj >> 16), byte(rawObj >> 8), byte(rawObj)})...)
		out = append(out, encodeOpeningTag(1)...)
		for _, propResult := range objResult.Results {
			out = append(out, encodeContextPrimitive(2, encodeUnsigned(uint32(propResult.PropertyIdentifier)))...)
			if propResult.ArrayIndex != nil {
				out = append(out, encodeContextPrimitive(3, encodeUnsigned(*propResult.ArrayIndex))...)
			}
			if len(propResult.Error) > 0 {
				out = append(out, encodeOpeningTag(5)...)
				out = append(out, propResult.Error...)
				out = append(out, encodeClosingTag(5)...)
			} else {
				out = append(out, encodeOpeningTag(4)...)
				out = append(out, propResult.PropertyValue...)
				out = append(out, encodeClosingTag(4)...)
			}
		}
		out = append(out, encodeClosingTag(1)...)
	}
	return out
}

func TestClientReadRange(t *testing.T) {
	transport := newTestNPDUTransport()
	ase, _ := NewASE(ASEConfig{InvokeTimeout: time.Second, MaxConcurrentInvokes: 4}, transport)
	clientRaw, err := NewClient(ase, ClientConfig{})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	client := clientRaw.(*clientImpl)

	dst, _ := netprim.NewAddress(netprim.LocalNetwork, []byte{0x01})
	objID, _ := types.NewObjectIdentifier(types.ObjectTypeAnalogInput, 7)
	arrayIndex := uint32(2)
	req := ReadRangeRequest{
		ObjectIdentifier:   objID,
		PropertyIdentifier: types.PropertyIdentifierPresentValue,
		ArrayIndex:         &arrayIndex,
		BySequenceNumber:   &ReadRangeBySequenceNumber{SequenceNumber: 10, Count: 5},
	}

	type result struct {
		ack ReadRangeACK
		err error
	}
	ch := make(chan result, 1)
	go func() {
		ack, callErr := client.ReadRange(context.Background(), dst, req)
		ch <- result{ack: ack, err: callErr}
	}()

	sent := <-transport.ch
	outbound, err := decodeAPDU(sent.packet.APDUBytes())
	if err != nil {
		t.Fatalf("decodeAPDU: %v", err)
	}
	if outbound.Type != PDUTypeConfirmedRequest {
		t.Fatalf("type = %v, want %v", outbound.Type, PDUTypeConfirmedRequest)
	}
	if outbound.ServiceChoice != ServiceChoiceReadRange {
		t.Fatalf("service = %v, want %v", outbound.ServiceChoice, ServiceChoiceReadRange)
	}

	decodedReq, err := decodeReadRangeRequestPayloadForTest(outbound.Payload)
	if err != nil {
		t.Fatalf("decodeReadRangeRequestPayloadForTest: %v", err)
	}
	if decodedReq.ObjectIdentifier != req.ObjectIdentifier {
		t.Fatalf("object identifier = %v, want %v", decodedReq.ObjectIdentifier, req.ObjectIdentifier)
	}
	if decodedReq.BySequenceNumber == nil || decodedReq.BySequenceNumber.Count != req.BySequenceNumber.Count {
		t.Fatalf("decoded range variant = %#v", decodedReq)
	}

	ackItemData := []byte{0x44, 0x41, 0x20, 0x00, 0x00}
	ackPayload := encodeReadRangeACKPayloadForTest(ReadRangeACK{
		ObjectIdentifier:   req.ObjectIdentifier,
		PropertyIdentifier: req.PropertyIdentifier,
		ArrayIndex:         req.ArrayIndex,
		ResultFlags:        []byte{0x00, 0x07},
		ItemCount:          func() *uint32 { v := uint32(1); return &v }(),
		ItemData:           ackItemData,
	})
	ackBytes, err := encodeAPDU(outboundAPDU{Type: PDUTypeComplexACK, InvokeID: outbound.InvokeID, ServiceChoice: ServiceChoiceReadRange, Payload: ackPayload})
	if err != nil {
		t.Fatalf("encodeAPDU: %v", err)
	}
	ackNPDU, _ := npdu.NewLocalAPDU(netprim.NetworkPriorityNormal, false, ackBytes)
	if err := ase.OnInboundNPDU(context.Background(), dst, *ackNPDU); err != nil {
		t.Fatalf("OnInboundNPDU: %v", err)
	}

	res := <-ch
	if res.err != nil {
		t.Fatalf("ReadRange: %v", res.err)
	}
	if res.ack.ObjectIdentifier != req.ObjectIdentifier {
		t.Fatalf("ack object identifier = %v, want %v", res.ack.ObjectIdentifier, req.ObjectIdentifier)
	}
	if res.ack.ItemCount == nil || *res.ack.ItemCount != 1 {
		t.Fatalf("ack item count = %v, want 1", res.ack.ItemCount)
	}
	if len(res.ack.ItemData) != len(ackItemData) {
		t.Fatalf("ack item data len = %d, want %d", len(res.ack.ItemData), len(ackItemData))
	}
}

func decodeReadRangeRequestPayloadForTest(payload []byte) (ReadRangeRequest, error) {
	cursor := 0
	objID, next, err := decodeExpectedContextObjectIdentifier(payload, cursor, 0)
	if err != nil {
		return ReadRangeRequest{}, err
	}
	cursor = next

	_, propBytes, next, err := decodeExpectedContextPrimitive(payload, cursor, 1)
	if err != nil {
		return ReadRangeRequest{}, err
	}
	propID, err := decodeUnsigned(propBytes)
	if err != nil {
		return ReadRangeRequest{}, err
	}
	cursor = next

	res := ReadRangeRequest{ObjectIdentifier: objID, PropertyIdentifier: types.PropertyIdentifier(propID)}
	if cursor < len(payload) && looksLikeContextPrimitiveTag(payload[cursor], 2) {
		_, arrBytes, next, err := decodeExpectedContextPrimitive(payload, cursor, 2)
		if err != nil {
			return ReadRangeRequest{}, err
		}
		idx, err := decodeUnsigned(arrBytes)
		if err != nil {
			return ReadRangeRequest{}, err
		}
		res.ArrayIndex = &idx
		cursor = next
	}

	if isOpeningTagAt(payload, cursor, 3) {
		cursor, err = expectOpeningTag(payload, cursor, 3)
		if err != nil {
			return ReadRangeRequest{}, err
		}
		_, refBytes, next, err := decodeExpectedContextPrimitive(payload, cursor, 0)
		if err != nil {
			return ReadRangeRequest{}, err
		}
		ref, _ := decodeUnsigned(refBytes)
		cursor = next
		_, countBytes, next, err := decodeExpectedContextPrimitive(payload, cursor, 1)
		if err != nil {
			return ReadRangeRequest{}, err
		}
		count, _ := decodeUnsigned(countBytes)
		cursor = next
		_, err = expectClosingTag(payload, cursor, 3)
		if err != nil {
			return ReadRangeRequest{}, err
		}
		res.ByPosition = &ReadRangeByPosition{ReferenceIndex: ref, Count: uint16(count)}
		return res, nil
	}

	if isOpeningTagAt(payload, cursor, 4) {
		cursor, err = expectOpeningTag(payload, cursor, 4)
		if err != nil {
			return ReadRangeRequest{}, err
		}
		_, seqBytes, next, err := decodeExpectedContextPrimitive(payload, cursor, 0)
		if err != nil {
			return ReadRangeRequest{}, err
		}
		seq, _ := decodeUnsigned(seqBytes)
		cursor = next
		_, countBytes, next, err := decodeExpectedContextPrimitive(payload, cursor, 1)
		if err != nil {
			return ReadRangeRequest{}, err
		}
		count, _ := decodeUnsigned(countBytes)
		cursor = next
		_, err = expectClosingTag(payload, cursor, 4)
		if err != nil {
			return ReadRangeRequest{}, err
		}
		res.BySequenceNumber = &ReadRangeBySequenceNumber{SequenceNumber: seq, Count: uint16(count)}
		return res, nil
	}

	return ReadRangeRequest{}, errors.New("missing range variant")
}

func encodeReadRangeACKPayloadForTest(ack ReadRangeACK) []byte {
	out := make([]byte, 0, 48+len(ack.ItemData))
	rawObj := uint32(ack.ObjectIdentifier)
	out = append(out, encodeContextPrimitive(0, []byte{byte(rawObj >> 24), byte(rawObj >> 16), byte(rawObj >> 8), byte(rawObj)})...)
	out = append(out, encodeContextPrimitive(1, encodeUnsigned(uint32(ack.PropertyIdentifier)))...)
	if ack.ArrayIndex != nil {
		out = append(out, encodeContextPrimitive(2, encodeUnsigned(*ack.ArrayIndex))...)
	}
	out = append(out, encodeContextPrimitive(3, ack.ResultFlags)...)
	if ack.ItemCount != nil {
		out = append(out, encodeContextPrimitive(4, encodeUnsigned(*ack.ItemCount))...)
	}
	out = append(out, encodeOpeningTag(5)...)
	out = append(out, ack.ItemData...)
	out = append(out, encodeClosingTag(5)...)
	return out
}

func Test_decodeErrorPayload(t *testing.T) {
	tests := []struct {
		//payload tag&length error class tag&length error code
		payload       []byte
		expectedCode  ErrorCode
		expectedClass ErrorClass
		expectedError error
	}{
		{
			payload:       nil,
			expectedCode:  ErrorCodeUnknown,
			expectedClass: ErrorClassUnknown,
			expectedError: ErrDecodeFailure,
		},
		{
			payload:       []byte{0x91, 0x01, 0x91, 0x1F},
			expectedCode:  ErrorCodeObjectUnknownObject,
			expectedClass: ErrorClassObject,
			expectedError: nil,
		},
		{
			payload:       []byte{0x91, 0x02, 0x91, 0x1B},
			expectedCode:  ErrorCodePropertyReadAccessDenied,
			expectedClass: ErrorClassProperty,
			expectedError: nil,
		},
		{
			payload:       []byte{0x91, 0x01, 0x91, 0x86}, // miss match: err 0x86 is class 0x02
			expectedCode:  ErrorCodeUnknown,
			expectedClass: ErrorClassUnknown,
			expectedError: ErrDecodeFailure,
		},
		{
			payload:       []byte{0x91, 0x02, 0x91, 0x86},
			expectedCode:  ErrorCodePropertyValueTooLong,
			expectedClass: ErrorClassProperty,
			expectedError: nil,
		},
		{
			payload:       []byte{0x91, 0x03, 0x91, 0x12},
			expectedCode:  ErrorCodeResourcesNoSpaceForObject,
			expectedClass: ErrorClassResources,
			expectedError: nil,
		},
		{
			payload:       []byte{0x91, 0x04, 0x91, 0x54},
			expectedCode:  ErrorCodeSecuritySuccess,
			expectedClass: ErrorClassSecurity,
			expectedError: nil,
		},
		{
			payload:       []byte{0x91, 0x05, 0x91, 0x05},
			expectedCode:  ErrorCodeServicesFileAccessDenied,
			expectedClass: ErrorClassServices,
			expectedError: nil,
		},
		{
			payload:       []byte{0x91, 0x06, 0x91, 0x23},
			expectedCode:  ErrorCodeVTUnknownVtSession,
			expectedClass: ErrorClassVT,
			expectedError: nil,
		},
		{
			payload:       []byte{0x91, 0x07, 0x91, 0x35},
			expectedCode:  ErrorCodeCommunicationAbortPreemptedByHigherPriorityTask,
			expectedClass: ErrorClassCommunication,
			expectedError: nil,
		},
		{
			payload:       []byte{0x91, 0x07, 0x91, 0xF3},
			expectedCode:  ErrorCodeUnknown,
			expectedClass: ErrorClassUnknown,
			expectedError: ErrDecodeFailure,
		},
		{
			payload:       []byte{0x91, 0x09, 0x91, 0x35},
			expectedCode:  ErrorCodeUnknown,
			expectedClass: ErrorClassUnknown,
			expectedError: ErrDecodeFailure,
		},

		{
			payload:       []byte{0x91, 0x00, 0x91, 0x00},
			expectedCode:  ErrorCodeOther,
			expectedClass: ErrorClassDevice,
			expectedError: nil,
		},
		{
			payload:       []byte{0x91, 0x01, 0x91, 0x00},
			expectedCode:  ErrorCodeOther,
			expectedClass: ErrorClassObject,
			expectedError: nil,
		},
		{
			payload:       []byte{0x91, 0x02, 0x91, 0x00},
			expectedCode:  ErrorCodeOther,
			expectedClass: ErrorClassProperty,
			expectedError: nil,
		},
		{
			payload:       []byte{0x91, 0x03, 0x91, 0x00},
			expectedCode:  ErrorCodeOther,
			expectedClass: ErrorClassResources,
			expectedError: nil,
		},
		{
			payload:       []byte{0x91, 0x04, 0x91, 0x00},
			expectedCode:  ErrorCodeOther,
			expectedClass: ErrorClassSecurity,
			expectedError: nil,
		},
		{
			payload:       []byte{0x91, 0x05, 0x91, 0x00},
			expectedCode:  ErrorCodeOther,
			expectedClass: ErrorClassServices,
			expectedError: nil,
		},
		{
			payload:       []byte{0x91, 0x06, 0x91, 0x00},
			expectedCode:  ErrorCodeOther,
			expectedClass: ErrorClassVT,
			expectedError: nil,
		},
		{
			payload:       []byte{0x91, 0x07, 0x91, 0x00},
			expectedCode:  ErrorCodeOther,
			expectedClass: ErrorClassCommunication,
			expectedError: nil,
		},
	}

	for _, tt := range tests {
		resClass, resCode, err := decodeErrorPayload(tt.payload)
		if !errors.Is(err, tt.expectedError) {
			t.Errorf("decodeErrorPayload(%v) error = %v, wantErr nil", tt.payload, err)
		}

		if resClass != tt.expectedClass {
			t.Errorf("decodeErrorPayload(%v) resClass = %v, want %v", tt.payload, resClass, tt.expectedClass)
		}

		if resCode != tt.expectedCode {
			t.Errorf("decodeErrorPayload(%v) resCode = %v, want %v", tt.payload, resCode, tt.expectedCode)
		}
	}
}
