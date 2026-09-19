package apdu

import (
	"errors"
	"testing"
)

func TestConfirmedClientMachineTransitions(t *testing.T) {
	tests := []struct {
		name       string
		events     []machineEvent
		wantState  machineState
		wantAction machineAction
		wantErr    error
	}{
		{
			name:       "request then simple ack completes",
			events:     []machineEvent{machineEventSendConfirmedRequest, machineEventInboundSimpleACK},
			wantState:  machineStateCompleted,
			wantAction: machineActionDeliverSimpleACK,
		},
		{
			name:       "request then complex ack completes",
			events:     []machineEvent{machineEventSendConfirmedRequest, machineEventInboundComplexACK},
			wantState:  machineStateCompleted,
			wantAction: machineActionDeliverComplexACK,
		},
		{
			name:       "request then reject aborts",
			events:     []machineEvent{machineEventSendConfirmedRequest, machineEventInboundReject},
			wantState:  machineStateAborted,
			wantAction: machineActionDeliverReject,
		},
		{
			name:       "request then timeout aborts",
			events:     []machineEvent{machineEventSendConfirmedRequest, machineEventTimeout},
			wantState:  machineStateAborted,
			wantAction: machineActionFailTimeout,
		},
		{
			name:       "close in completed state is noop",
			events:     []machineEvent{machineEventSendConfirmedRequest, machineEventInboundSimpleACK, machineEventClose},
			wantState:  machineStateCompleted,
			wantAction: machineActionNone,
		},
		{
			name:       "close in aborted state is noop",
			events:     []machineEvent{machineEventSendConfirmedRequest, machineEventTimeout, machineEventClose},
			wantState:  machineStateAborted,
			wantAction: machineActionNone,
		},
		{
			name:       "segment ack is scaffolded but unsupported",
			events:     []machineEvent{machineEventSendConfirmedRequest, machineEventInboundSegmentACK},
			wantState:  machineStateAwaitResponse,
			wantAction: machineActionNone,
			wantErr:    ErrSegmentationNotSupported,
		},
		{
			name:       "terminal APDU before request is invalid",
			events:     []machineEvent{machineEventInboundSimpleACK},
			wantState:  machineStateIdle,
			wantAction: machineActionNone,
			wantErr:    ErrInvalidStateTransition,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			machine := newConfirmedClientMachine()
			var gotOutput machineOutput
			var err error

			for _, event := range tt.events {
				input := machineInput{InboundAPDU: &inboundAPDU{Type: pduTypeForEvent(event), InvokeID: machine.variables.invokeID}}
				if event == machineEventSendConfirmedRequest {
					input.ConfirmedRequest = &ConfirmedRequest{ServiceChoice: ServiceChoiceReadProperty, Payload: []byte{0x01}}
				}
				gotOutput, err = machine.Handle(event, input)
				if err != nil {
					break
				}
			}

			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("Handle() error = %v, want %v", err, tt.wantErr)
			}
			if machine.State() != tt.wantState {
				t.Fatalf("State() = %v, want %v", machine.State(), tt.wantState)
			}
			if gotOutput.action != tt.wantAction {
				t.Fatalf("action = %v, want %v", gotOutput.action, tt.wantAction)
			}
		})
	}
}

// pduTypeForEvent maps an inbound terminal-PDU machine event to the PDUType
// used when constructing a test machineInput.  Events without an associated
// PDU type return PDUTypeConfirmedRequest as a harmless zero-value stand-in.
func pduTypeForEvent(event machineEvent) PDUType {
	switch event {
	case machineEventInboundSimpleACK:
		return PDUTypeSimpleACK
	case machineEventInboundComplexACK:
		return PDUTypeComplexACK
	case machineEventInboundError:
		return PDUTypeError
	case machineEventInboundReject:
		return PDUTypeReject
	case machineEventInboundAbort:
		return PDUTypeAbort
	default:
		return PDUTypeConfirmedRequest
	}
}

func TestConfirmedServerMachineTransitions(t *testing.T) {
	tests := []struct {
		name           string
		events         []machineEvent
		handlerPayload []byte
		cfg            confirmedServerMachineConfig
		wantState      machineState
		wantAction     machineAction
		wantErr        error
	}{
		{
			name:       "request then simple ack response completes",
			events:     []machineEvent{machineEventInboundConfirmedRequest, machineEventResponseReady},
			wantState:  machineStateCompleted,
			wantAction: machineActionSendSimpleACK,
		},
		{
			name:           "request then complex ack response completes",
			events:         []machineEvent{machineEventInboundConfirmedRequest, machineEventResponseReady},
			handlerPayload: []byte{0x01},
			wantState:      machineStateCompleted,
			wantAction:     machineActionSendComplexACK,
		},
		{
			name:       "segmented response requirement aborts",
			events:     []machineEvent{machineEventInboundConfirmedRequest, machineEventResponseRequiresSegmentation},
			wantState:  machineStateAborted,
			wantAction: machineActionSendAbort,
		},
		{
			name:           "oversized response aborts",
			events:         []machineEvent{machineEventInboundConfirmedRequest, machineEventResponseReady},
			handlerPayload: []byte{0x01, 0x02},
			cfg:            confirmedServerMachineConfig{maxAPDUSizeAccepted: 1},
			wantState:      machineStateAborted,
			wantAction:     machineActionSendAbort,
		},
		{
			name:       "handler error aborts",
			events:     []machineEvent{machineEventInboundConfirmedRequest, machineEventHandlerError},
			wantState:  machineStateAborted,
			wantAction: machineActionSendAbort,
		},
		{
			name:       "cannot send after response aborts",
			events:     []machineEvent{machineEventInboundConfirmedRequest, machineEventResponseReady, machineEventCannotSend},
			wantState:  machineStateAborted,
			wantAction: machineActionDeliverCannotSend,
		},
		{
			name:       "close in completed state is noop",
			events:     []machineEvent{machineEventInboundConfirmedRequest, machineEventResponseReady, machineEventClose},
			wantState:  machineStateCompleted,
			wantAction: machineActionNone,
		},
		{
			name:       "close in aborted state is noop",
			events:     []machineEvent{machineEventInboundConfirmedRequest, machineEventHandlerError, machineEventClose},
			wantState:  machineStateAborted,
			wantAction: machineActionNone,
		},
		{
			name:       "response before request is invalid",
			events:     []machineEvent{machineEventResponseReady},
			wantState:  machineStateIdle,
			wantAction: machineActionNone,
			wantErr:    ErrInvalidStateTransition,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			machine := newConfirmedServerMachineWithConfig(tt.cfg)
			var gotOutput machineOutput
			var err error

			for _, event := range tt.events {
				input := machineInput{}
				if event == machineEventResponseReady || event == machineEventResponseRequiresSegmentation {
					input.HandlerResult = &ServiceResult{Payload: tt.handlerPayload}
				}
				gotOutput, err = machine.Handle(event, input)
				if err != nil {
					break
				}
			}

			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("Handle() error = %v, want %v", err, tt.wantErr)
			}
			if machine.State() != tt.wantState {
				t.Fatalf("State() = %v, want %v", machine.State(), tt.wantState)
			}
			if gotOutput.action != tt.wantAction {
				t.Fatalf("action = %v, want %v", gotOutput.action, tt.wantAction)
			}
		})
	}
}

func TestConfirmedServerMachineAbortReasonMapping(t *testing.T) {
	tests := []struct {
		name       string
		cfg        confirmedServerMachineConfig
		firstInput machineInput
		abortEvent machineEvent
		abortInput machineInput
		wantReason AbortReason
	}{
		{
			name: "oversized response maps to apdu-too-long",
			cfg:  confirmedServerMachineConfig{maxAPDUSizeAccepted: 1},
			firstInput: machineInput{InboundAPDU: &inboundAPDU{
				Type:          PDUTypeConfirmedRequest,
				InvokeID:      1,
				ServiceChoice: ServiceChoiceReadProperty,
				Payload:       []byte{0x01},
			}},
			abortEvent: machineEventResponseReady,
			abortInput: machineInput{HandlerResult: &ServiceResult{Payload: []byte{0x01, 0x02}}},
			wantReason: AbortReasonAPDUTooLong,
		},
		{
			name: "response requires segmentation maps to segmentation-not-supported",
			cfg:  confirmedServerMachineConfig{},
			firstInput: machineInput{InboundAPDU: &inboundAPDU{
				Type:          PDUTypeConfirmedRequest,
				InvokeID:      2,
				ServiceChoice: ServiceChoiceReadProperty,
				Payload:       []byte{0x01},
			}},
			abortEvent: machineEventResponseRequiresSegmentation,
			abortInput: machineInput{HandlerResult: &ServiceResult{Payload: []byte{0x01}}},
			wantReason: AbortReasonSegmentationNotSupported,
		},
		{
			name: "segmented receive timeout maps to tsm-timeout",
			cfg:  confirmedServerMachineConfig{segmentation: SegmentationSupportBoth},
			firstInput: machineInput{InboundAPDU: &inboundAPDU{
				Type:               PDUTypeConfirmedRequest,
				SegmentedMessage:   true,
				MoreFollows:        true,
				InvokeID:           3,
				SequenceNumber:     0,
				ProposedWindowSize: 1,
				ServiceChoice:      ServiceChoiceReadProperty,
				Payload:            []byte{0xAA},
			}},
			abortEvent: machineEventSegmentTimeout,
			abortInput: machineInput{},
			wantReason: AbortReasonTSMTimeout,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			machine := newConfirmedServerMachineWithConfig(tt.cfg)

			if _, err := machine.Handle(machineEventInboundConfirmedRequest, tt.firstInput); err != nil {
				t.Fatalf("Handle(inbound-confirmed-request) error = %v", err)
			}

			out, err := machine.Handle(tt.abortEvent, tt.abortInput)
			if err != nil {
				t.Fatalf("Handle(%v) error = %v", tt.abortEvent, err)
			}

			if out.action != machineActionSendAbort {
				t.Fatalf("action = %v, want %v", out.action, machineActionSendAbort)
			}

			if out.OutboundAPDU == nil {
				t.Fatal("OutboundAPDU = nil, want abort APDU")
			}

			if out.OutboundAPDU.Type != PDUTypeAbort {
				t.Fatalf("abort type = %v, want %v", out.OutboundAPDU.Type, PDUTypeAbort)
			}

			if len(out.OutboundAPDU.Payload) != 1 || out.OutboundAPDU.Payload[0] != byte(tt.wantReason) {
				t.Fatalf("abort payload = %v, want [%d]", out.OutboundAPDU.Payload, byte(tt.wantReason))
			}
		})
	}
}

func TestMachineEventForInboundTerminalPDU(t *testing.T) {
	tests := []struct {
		name    string
		pduType PDUType
		want    machineEvent
		wantErr error
	}{
		{name: "simple ack", pduType: PDUTypeSimpleACK, want: machineEventInboundSimpleACK},
		{name: "complex ack", pduType: PDUTypeComplexACK, want: machineEventInboundComplexACK},
		{name: "error", pduType: PDUTypeError, want: machineEventInboundError},
		{name: "reject", pduType: PDUTypeReject, want: machineEventInboundReject},
		{name: "abort", pduType: PDUTypeAbort, want: machineEventInboundAbort},
		{name: "invalid", pduType: PDUTypeConfirmedRequest, wantErr: ErrInvalidPDUType},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := machineEventForInboundTerminalPDU(tt.pduType)
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("machineEventForInboundTerminalPDU() error = %v, want %v", err, tt.wantErr)
			}
			if got != tt.want {
				t.Fatalf("machineEventForInboundTerminalPDU() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestTransitionForConfirmedClientInboundNonSegmentedEvent(t *testing.T) {
	tests := []struct {
		name       string
		event      machineEvent
		wantState  machineState
		wantAction machineAction
		wantOK     bool
	}{
		{
			name:       "simple ack",
			event:      machineEventInboundSimpleACK,
			wantState:  machineStateCompleted,
			wantAction: machineActionDeliverSimpleACK,
			wantOK:     true,
		},
		{
			name:       "error",
			event:      machineEventInboundError,
			wantState:  machineStateAborted,
			wantAction: machineActionDeliverError,
			wantOK:     true,
		},
		{
			name:   "unsupported event",
			event:  machineEventTimeout,
			wantOK: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := transitionForConfirmedClientInboundNonSegmentedEvent(tt.event)
			if ok != tt.wantOK {
				t.Fatalf("transitionForConfirmedClientInboundNonSegmentedEvent() ok = %v, want %v", ok, tt.wantOK)
			}
			if !ok {
				return
			}
			if got.nextState != tt.wantState {
				t.Fatalf("transition nextState = %v, want %v", got.nextState, tt.wantState)
			}
			if got.action != tt.wantAction {
				t.Fatalf("transition action = %v, want %v", got.action, tt.wantAction)
			}
		})
	}
}

func TestTransitionForConfirmedServerResponseNonSegmentedEvent(t *testing.T) {
	tests := []struct {
		name       string
		event      machineEvent
		wantState  machineState
		wantAction machineAction
		wantOK     bool
	}{
		{
			name:       "response ready",
			event:      machineEventResponseReady,
			wantState:  machineStateCompleted,
			wantAction: machineActionNone,
			wantOK:     true,
		},
		{
			name:   "unsupported event",
			event:  machineEventHandlerError,
			wantOK: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := transitionForConfirmedServerResponseNonSegmentedEvent(tt.event)
			if ok != tt.wantOK {
				t.Fatalf("transitionForConfirmedServerResponseNonSegmentedEvent() ok = %v, want %v", ok, tt.wantOK)
			}
			if !ok {
				return
			}
			if got.nextState != tt.wantState {
				t.Fatalf("transition nextState = %v, want %v", got.nextState, tt.wantState)
			}
			if got.action != tt.wantAction {
				t.Fatalf("transition action = %v, want %v", got.action, tt.wantAction)
			}
		})
	}
}

func TestNewConfirmedClientMachineWithConfigInitializesVariables(t *testing.T) {
	machine := newConfirmedClientMachineWithConfig(confirmedClientMachineConfig{
		invokeID:             7,
		segmentation:         SegmentationSupportTransmit,
		maxSegmentsAccepted:  MaxSegments16,
		maxAPDUSizeAccepted:  480,
		requestPayloadLength: 12,
	})

	if machine.State() != machineStateIdle {
		t.Fatalf("State() = %v, want %v", machine.State(), machineStateIdle)
	}
	if machine.variables.invokeID != 7 {
		t.Fatalf("invokeID = %d, want 7", machine.variables.invokeID)
	}
	if machine.variables.segmentation != SegmentationSupportTransmit {
		t.Fatalf("segmentation = %v, want %v", machine.variables.segmentation, SegmentationSupportTransmit)
	}
	if machine.variables.maxSegmentsAccepted != MaxSegments16 {
		t.Fatalf("maxSegmentsAccepted = %v, want %v", machine.variables.maxSegmentsAccepted, MaxSegments16)
	}
	if machine.variables.maxAPDUSizeAccepted != 480 {
		t.Fatalf("maxAPDUSizeAccepted = %d, want 480", machine.variables.maxAPDUSizeAccepted)
	}
	if machine.variables.requestPayloadLength != 12 {
		t.Fatalf("requestPayloadLength = %d, want 12", machine.variables.requestPayloadLength)
	}
	if machine.variables.responsePDUTypeSet {
		t.Fatalf("responsePDUTypeSet = true, want false")
	}
	if machine.variables.confirmResultSet {
		t.Fatalf("confirmResultSet = true, want false")
	}
	if machine.variables.segmented.sequenceNumber != 0 ||
		machine.variables.segmented.initialSequenceNumber != 0 ||
		machine.variables.segmented.lastSequenceNumber != 0 ||
		machine.variables.segmented.actualWindowSize != 0 {
		t.Fatalf("segmented = %#v, want zero value fields", machine.variables.segmented)
	}
	if machine.variables.segmented.bufferedPayloads != nil || machine.variables.segmented.bufferedMoreFollows != nil {
		t.Fatalf("segmented buffered maps = %#v/%#v, want nil", machine.variables.segmented.bufferedPayloads, machine.variables.segmented.bufferedMoreFollows)
	}
}

func TestConfirmedClientMachineBuildConfirmViaHandle(t *testing.T) {
	tests := []struct {
		name        string
		pduType     PDUType
		payload     []byte
		wantResult  ConfirmResult
		wantPayload []byte
		wantErr     error
	}{
		{name: "simple ack", pduType: PDUTypeSimpleACK, wantResult: ConfirmResultPositiveAck, wantErr: (*TransactionError)(nil)},
		{name: "complex ack with payload", pduType: PDUTypeComplexACK, payload: []byte{1, 2, 3}, wantResult: ConfirmResultPositiveAck, wantPayload: []byte{1, 2, 3}, wantErr: (*TransactionError)(nil)},
		{name: "error", pduType: PDUTypeError, payload: []byte{4, 5}, wantResult: ConfirmResultError, wantErr: ErrRemoteError},
		{name: "reject", pduType: PDUTypeReject, payload: []byte{6}, wantResult: ConfirmResultReject, wantErr: ErrRemoteReject},
		{name: "abort", pduType: PDUTypeAbort, payload: []byte{7, 8, 9}, wantResult: ConfirmResultAbort, wantErr: ErrRemoteAbort},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			machine := newConfirmedClientMachineWithConfig(confirmedClientMachineConfig{invokeID: 3})
			// Advance to await-response first.
			if _, err := machine.Handle(machineEventSendConfirmedRequest, machineInput{ConfirmedRequest: &ConfirmedRequest{ServiceChoice: ServiceChoiceReadProperty}}); err != nil {
				t.Fatalf("setup Handle() error: %v", err)
			}

			event, err := machineEventForInboundTerminalPDU(tt.pduType)
			if err != nil {
				t.Fatalf("machineEventForInboundTerminalPDU() error: %v", err)
			}

			out, err := machine.Handle(event, machineInput{
				InboundAPDU: &inboundAPDU{Type: tt.pduType, InvokeID: 3, Payload: tt.payload},
			})
			if !errors.Is(err, nil) {
				t.Fatalf("Handle() error = %v, want nil", err)
			}

			if out.Confirm == nil {
				t.Fatalf("Confirm is nil, expected non-nil")
			}
			if out.Confirm.confirm.Result != tt.wantResult {
				t.Fatalf("Confirm.Result = %v, want %v", out.Confirm.confirm.Result, tt.wantResult)
			}
			if out.Confirm.confirm.InvokeID != 3 {
				t.Fatalf("Confirm.InvokeID = %v, want 3", out.Confirm.confirm.InvokeID)
			}
			if !errors.Is(out.Confirm.err, tt.wantErr) {
				t.Fatalf("Confirm.err = %v, want %v", out.Confirm.err, tt.wantErr)
			}
			if tt.wantPayload != nil {
				if out.Confirm.confirm.ServiceResponse == nil {
					t.Fatalf("ServiceResponse is nil, want non-nil")
				}
				if string(out.Confirm.confirm.ServiceResponse.Payload) != string(tt.wantPayload) {
					t.Fatalf("Payload = %v, want %v", out.Confirm.confirm.ServiceResponse.Payload, tt.wantPayload)
				}
			} else if tt.pduType == PDUTypeSimpleACK {
				if out.Confirm.confirm.ServiceResponse != nil {
					t.Fatalf("ServiceResponse should be nil for SimpleACK")
				}
			}
		})
	}
}

// TestConfirmedClientMachineBuildConfirmNilAPDU verifies that nil terminal APDU
// input is rejected as an invalid transition and does not produce a Confirm.
func TestConfirmedClientMachineBuildConfirmNilAPDU(t *testing.T) {
	machine := newConfirmedClientMachine()
	if _, err := machine.Handle(machineEventSendConfirmedRequest, machineInput{ConfirmedRequest: &ConfirmedRequest{ServiceChoice: ServiceChoiceReadProperty}}); err != nil {
		t.Fatalf("setup error: %v", err)
	}
	out, err := machine.Handle(machineEventInboundSimpleACK, machineInput{InboundAPDU: nil})
	if !errors.Is(err, ErrInvalidStateTransition) {
		t.Fatalf("Handle() error = %v, want %v", err, ErrInvalidStateTransition)
	}
	if out.Confirm != nil {
		t.Fatalf("Confirm = %#v, want nil", out.Confirm)
	}
	if machine.State() != machineStateAwaitResponse {
		t.Fatalf("State() = %v, want %v", machine.State(), machineStateAwaitResponse)
	}
}

func TestConfirmedClientMachineRejectsMismatchedTerminalEventAndPDUType(t *testing.T) {
	machine := newConfirmedClientMachine()
	if _, err := machine.Handle(machineEventSendConfirmedRequest, machineInput{ConfirmedRequest: &ConfirmedRequest{ServiceChoice: ServiceChoiceReadProperty}}); err != nil {
		t.Fatalf("setup error: %v", err)
	}

	out, err := machine.Handle(machineEventInboundSimpleACK, machineInput{InboundAPDU: &inboundAPDU{Type: PDUTypeAbort}})
	if !errors.Is(err, ErrInvalidStateTransition) {
		t.Fatalf("Handle() error = %v, want %v", err, ErrInvalidStateTransition)
	}
	if out.Confirm != nil {
		t.Fatalf("Confirm = %#v, want nil", out.Confirm)
	}
	if machine.State() != machineStateAwaitResponse {
		t.Fatalf("State() = %v, want %v", machine.State(), machineStateAwaitResponse)
	}
}

func TestConfirmedClientMachineFailureEventsInAwaitResponse(t *testing.T) {
	tests := []struct {
		name       string
		event      machineEvent
		cause      error
		wantAction machineAction
		wantResult ConfirmResult
		wantErr    error
	}{
		{
			name:       "cannot send",
			event:      machineEventCannotSend,
			cause:      ErrTransportFailure,
			wantAction: machineActionDeliverCannotSend,
			wantResult: ConfirmResultCannotSend,
			wantErr:    ErrTransportFailure,
		},
		{
			name:       "unexpected pdu",
			event:      machineEventUnexpectedPDU,
			cause:      ErrUnexpectedPDU,
			wantAction: machineActionDeliverUnexpectedPDU,
			wantResult: ConfirmResultUnexpectedPDU,
			wantErr:    ErrUnexpectedPDU,
		},
		{
			name:       "security error",
			event:      machineEventSecurityErrorReceived,
			cause:      ErrSecurityError,
			wantAction: machineActionDeliverSecurityError,
			wantResult: ConfirmResultSecurityError,
			wantErr:    ErrSecurityError,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			machine := newConfirmedClientMachineWithConfig(confirmedClientMachineConfig{invokeID: 19})
			if _, err := machine.Handle(machineEventSendConfirmedRequest, machineInput{ConfirmedRequest: &ConfirmedRequest{ServiceChoice: ServiceChoiceReadProperty}}); err != nil {
				t.Fatalf("setup Handle() error: %v", err)
			}

			out, err := machine.Handle(tt.event, machineInput{Cause: tt.cause})
			if err != nil {
				t.Fatalf("Handle() error = %v, want nil", err)
			}
			if out.action != tt.wantAction {
				t.Fatalf("action = %v, want %v", out.action, tt.wantAction)
			}
			if out.Confirm == nil {
				t.Fatalf("Confirm is nil, expected non-nil")
			}
			if out.Confirm.confirm.Result != tt.wantResult {
				t.Fatalf("Confirm.Result = %v, want %v", out.Confirm.confirm.Result, tt.wantResult)
			}
			if !errors.Is(out.Confirm.err, tt.wantErr) {
				t.Fatalf("Confirm.err = %v, want %v", out.Confirm.err, tt.wantErr)
			}
			if machine.State() != machineStateAborted {
				t.Fatalf("State() = %v, want %v", machine.State(), machineStateAborted)
			}
		})
	}
}

func TestConfirmedClientMachineSendRequiresSegmentation(t *testing.T) {
	machine := newConfirmedClientMachineWithConfig(confirmedClientMachineConfig{maxAPDUSizeAccepted: 1})
	_, err := machine.Handle(machineEventSendConfirmedRequest, machineInput{
		ConfirmedRequest: &ConfirmedRequest{ServiceChoice: ServiceChoiceReadProperty, Payload: []byte{0x01, 0x02}},
	})
	if !errors.Is(err, ErrSegmentationNotSupported) {
		t.Fatalf("Handle() error = %v, want %v", err, ErrSegmentationNotSupported)
	}
	if machine.State() != machineStateIdle {
		t.Fatalf("State() = %v, want %v", machine.State(), machineStateIdle)
	}
}

func TestConfirmedClientMachineSendAtExactAPDULimitDoesNotRequireSegmentation(t *testing.T) {
	machine := newConfirmedClientMachineWithConfig(confirmedClientMachineConfig{maxAPDUSizeAccepted: confirmedRequestAPDUHeaderLength + 2})

	out, err := machine.Handle(machineEventSendConfirmedRequest, machineInput{
		ConfirmedRequest: &ConfirmedRequest{ServiceChoice: ServiceChoiceReadProperty, Payload: []byte{0x01, 0x02}},
	})
	if err != nil {
		t.Fatalf("Handle() error = %v, want nil", err)
	}
	if out.OutboundAPDU == nil {
		t.Fatal("OutboundAPDU is nil, want non-nil")
	}
}

func TestConfirmedClientMachineTimeoutTriggersResendWithinRetryBudget(t *testing.T) {
	machine := newConfirmedClientMachineWithConfig(confirmedClientMachineConfig{invokeID: 21, maxRetries: 2})

	first, err := machine.Handle(machineEventSendConfirmedRequest, machineInput{
		ConfirmedRequest: &ConfirmedRequest{ServiceChoice: ServiceChoiceReadProperty, Payload: []byte{0xAA, 0xBB}},
	})
	if err != nil {
		t.Fatalf("Handle(send) error = %v, want nil", err)
	}
	if first.OutboundAPDU == nil {
		t.Fatalf("first OutboundAPDU is nil")
	}

	resend, err := machine.Handle(machineEventTimeout, machineInput{})
	if err != nil {
		t.Fatalf("Handle(timeout) error = %v, want nil", err)
	}
	if resend.action != machineActionResendConfirmedRequest {
		t.Fatalf("action = %v, want %v", resend.action, machineActionResendConfirmedRequest)
	}
	if resend.OutboundAPDU == nil {
		t.Fatalf("resend OutboundAPDU is nil")
	}
	if resend.OutboundAPDU.Type != PDUTypeConfirmedRequest {
		t.Fatalf("resend type = %v, want %v", resend.OutboundAPDU.Type, PDUTypeConfirmedRequest)
	}
	if resend.OutboundAPDU.InvokeID != 21 {
		t.Fatalf("resend invokeID = %d, want 21", resend.OutboundAPDU.InvokeID)
	}
	if resend.OutboundAPDU.ServiceChoice != ServiceChoiceReadProperty {
		t.Fatalf("resend service choice = %v, want %v", resend.OutboundAPDU.ServiceChoice, ServiceChoiceReadProperty)
	}
	if string(resend.OutboundAPDU.Payload) != string([]byte{0xAA, 0xBB}) {
		t.Fatalf("resend payload = %v, want [170 187]", resend.OutboundAPDU.Payload)
	}
	if machine.State() != machineStateAwaitResponse {
		t.Fatalf("State() = %v, want %v", machine.State(), machineStateAwaitResponse)
	}
}

func TestConfirmedClientMachineTimeoutExhaustsRetryBudget(t *testing.T) {
	machine := newConfirmedClientMachineWithConfig(confirmedClientMachineConfig{maxRetries: 1})
	if _, err := machine.Handle(machineEventSendConfirmedRequest, machineInput{
		ConfirmedRequest: &ConfirmedRequest{ServiceChoice: ServiceChoiceReadProperty, Payload: []byte{0x01}},
	}); err != nil {
		t.Fatalf("setup Handle(send) error = %v", err)
	}

	firstTimeout, err := machine.Handle(machineEventTimeout, machineInput{})
	if err != nil {
		t.Fatalf("first Handle(timeout) error = %v, want nil", err)
	}
	if firstTimeout.action != machineActionResendConfirmedRequest {
		t.Fatalf("first timeout action = %v, want %v", firstTimeout.action, machineActionResendConfirmedRequest)
	}

	secondTimeout, err := machine.Handle(machineEventTimeout, machineInput{})
	if err != nil {
		t.Fatalf("second Handle(timeout) error = %v, want nil", err)
	}
	if secondTimeout.action != machineActionFailTimeout {
		t.Fatalf("second timeout action = %v, want %v", secondTimeout.action, machineActionFailTimeout)
	}
	if machine.State() != machineStateAborted {
		t.Fatalf("State() = %v, want %v", machine.State(), machineStateAborted)
	}
}

func TestNewConfirmedServerMachineWithConfigInitializesVariables(t *testing.T) {
	machine := newConfirmedServerMachineWithConfig(confirmedServerMachineConfig{
		invokeID:                     9,
		serviceChoice:                ServiceChoiceReadProperty,
		requesterSegmentation:        SegmentationSupportReceive,
		requesterMaxSegmentsAccepted: MaxSegments8,
		requesterMaxAPDUSizeAccepted: 1024,
		segmentation:                 SegmentationSupportBoth,
		preferredWindowSize:          4,
		maxAPDUSizeAccepted:          1476,
		requestPayloadLength:         6,
	})

	if machine.State() != machineStateIdle {
		t.Fatalf("State() = %v, want %v", machine.State(), machineStateIdle)
	}
	if machine.variables.invokeID != 9 {
		t.Fatalf("invokeID = %d, want 9", machine.variables.invokeID)
	}
	if machine.variables.serviceChoice != ServiceChoiceReadProperty {
		t.Fatalf("serviceChoice = %v, want %v", machine.variables.serviceChoice, ServiceChoiceReadProperty)
	}
	if machine.variables.requesterSegmentation != SegmentationSupportReceive {
		t.Fatalf("requesterSegmentation = %v, want %v", machine.variables.requesterSegmentation, SegmentationSupportReceive)
	}
	if machine.variables.requesterMaxSegmentsAccepted != MaxSegments8 {
		t.Fatalf("requesterMaxSegmentsAccepted = %v, want %v", machine.variables.requesterMaxSegmentsAccepted, MaxSegments8)
	}
	if machine.variables.requesterMaxAPDUSizeAccepted != 1024 {
		t.Fatalf("requesterMaxAPDUSizeAccepted = %d, want 1024", machine.variables.requesterMaxAPDUSizeAccepted)
	}
	if machine.variables.segmentation != SegmentationSupportBoth {
		t.Fatalf("segmentation = %v, want %v", machine.variables.segmentation, SegmentationSupportBoth)
	}
	if machine.variables.preferredWindowSize != 4 {
		t.Fatalf("preferredWindowSize = %d, want 4", machine.variables.preferredWindowSize)
	}
	if machine.variables.maxAPDUSizeAccepted != 1476 {
		t.Fatalf("maxAPDUSizeAccepted = %d, want 1476", machine.variables.maxAPDUSizeAccepted)
	}
	if machine.variables.requestPayloadLength != 6 {
		t.Fatalf("requestPayloadLength = %d, want 6", machine.variables.requestPayloadLength)
	}
	if machine.variables.responsePDUTypeSet {
		t.Fatalf("responsePDUTypeSet = true, want false")
	}
	if machine.variables.segmented.sequenceNumber != 0 ||
		machine.variables.segmented.initialSequenceNumber != 0 ||
		machine.variables.segmented.lastSequenceNumber != 0 ||
		machine.variables.segmented.actualWindowSize != 0 {
		t.Fatalf("segmented = %#v, want zero value fields", machine.variables.segmented)
	}
	if machine.variables.segmented.bufferedPayloads != nil || machine.variables.segmented.bufferedMoreFollows != nil {
		t.Fatalf("segmented buffered maps = %#v/%#v, want nil", machine.variables.segmented.bufferedPayloads, machine.variables.segmented.bufferedMoreFollows)
	}
	if machine.variables.segmented.maxDuplicateCount != defaultMaxDuplicateCount {
		t.Fatalf("maxDuplicateCount = %d, want %d", machine.variables.segmented.maxDuplicateCount, defaultMaxDuplicateCount)
	}
}

func TestConfirmedServerMachineBuildOutboundAPDUViaHandle(t *testing.T) {
	tests := []struct {
		name           string
		handlerPayload []byte
		event          machineEvent
		responseType   *ConfirmedResponseType
		wantPDUType    PDUType
		wantPayload    []byte
		wantErr        error
	}{
		{
			name:        "simple ack yields nil payload",
			event:       machineEventResponseReady,
			wantPDUType: PDUTypeSimpleACK,
			wantPayload: nil,
		},
		{
			name:           "complex ack with payload",
			handlerPayload: []byte{10, 20, 30},
			event:          machineEventResponseReady,
			wantPDUType:    PDUTypeComplexACK,
			wantPayload:    []byte{10, 20, 30},
		},
		{
			name:        "handler error yields abort",
			event:       machineEventHandlerError,
			wantPDUType: PDUTypeAbort,
			wantPayload: nil,
			wantErr:     nil,
		},
		{
			name:  "handler error yields error when requested",
			event: machineEventHandlerError,
			responseType: func() *ConfirmedResponseType {
				v := ConfirmedResponseTypeError
				return &v
			}(),
			wantPDUType: PDUTypeError,
			wantPayload: nil,
			wantErr:     nil,
		},
		{
			name:  "handler error yields reject when requested",
			event: machineEventHandlerError,
			responseType: func() *ConfirmedResponseType {
				v := ConfirmedResponseTypeReject
				return &v
			}(),
			wantPDUType: PDUTypeReject,
			wantPayload: nil,
			wantErr:     nil,
		},
		{
			name:        "response requires segmentation yields abort",
			event:       machineEventResponseRequiresSegmentation,
			wantPDUType: PDUTypeAbort,
			wantPayload: []byte{byte(AbortReasonSegmentationNotSupported)},
			wantErr:     nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			machine := newConfirmedServerMachineWithConfig(confirmedServerMachineConfig{
				invokeID:      5,
				serviceChoice: ServiceChoiceReadProperty,
			})
			// Advance to await-response.
			if _, err := machine.Handle(machineEventInboundConfirmedRequest, machineInput{}); err != nil {
				t.Fatalf("setup Handle() error: %v", err)
			}

			handlerResult := &ServiceResult{}
			if tt.handlerPayload != nil {
				handlerResult = &ServiceResult{Payload: tt.handlerPayload}
			}

			out, err := machine.Handle(tt.event, machineInput{HandlerResult: handlerResult, HandlerResponseType: tt.responseType})
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("Handle() error = %v, want %v", err, tt.wantErr)
			}
			if tt.wantErr != nil {
				return
			}

			if out.OutboundAPDU == nil {
				t.Fatalf("OutboundAPDU is nil, expected non-nil")
			}
			if out.OutboundAPDU.Type != tt.wantPDUType {
				t.Fatalf("OutboundAPDU.Type = %v, want %v", out.OutboundAPDU.Type, tt.wantPDUType)
			}
			if out.OutboundAPDU.InvokeID != 5 {
				t.Fatalf("OutboundAPDU.InvokeID = %v, want 5", out.OutboundAPDU.InvokeID)
			}
			if inboundAPDUCarriesServiceContext(out.OutboundAPDU.Type) && out.OutboundAPDU.ServiceChoice != ServiceChoiceReadProperty {
				t.Fatalf("OutboundAPDU.ServiceChoice = %v, want %v", out.OutboundAPDU.ServiceChoice, ServiceChoiceReadProperty)
			}
			if string(out.OutboundAPDU.Payload) != string(tt.wantPayload) {
				t.Fatalf("OutboundAPDU.Payload = %v, want %v", out.OutboundAPDU.Payload, tt.wantPayload)
			}
		})
	}
}

func TestSegmentedEventVariables(t *testing.T) {
	if _, ok := confirmedClientInboundSegmentedEvents[machineEventInboundSegmentACK]; !ok {
		t.Fatalf("confirmedClientInboundSegmentedEvents missing %v", machineEventInboundSegmentACK)
	}
	if _, ok := confirmedServerInboundSegmentedEvents[machineEventInboundSegmentACK]; !ok {
		t.Fatalf("confirmedServerInboundSegmentedEvents missing %v", machineEventInboundSegmentACK)
	}
	if _, ok := confirmedServerResponseSegmentedEvents[machineEventResponseRequiresSegmentation]; !ok {
		t.Fatalf("confirmedServerResponseSegmentedEvents missing %v", machineEventResponseRequiresSegmentation)
	}
	if _, ok := inboundTerminalPDUSegmentedEvents[PDUTypeSegmentACK]; !ok {
		t.Fatalf("inboundTerminalPDUSegmentedEvents missing %v", PDUTypeSegmentACK)
	}
}

func TestUnconfirmedClientMachineTransitions(t *testing.T) {
	tests := []struct {
		name       string
		events     []machineEvent
		wantState  machineState
		wantAction machineAction
		wantErr    error
	}{
		{
			name:       "send completes immediately",
			events:     []machineEvent{machineEventSendUnconfirmedRequest},
			wantState:  machineStateCompleted,
			wantAction: machineActionSendUnconfirmedRequest,
		},
		{
			name:       "close in completed state is noop",
			events:     []machineEvent{machineEventSendUnconfirmedRequest, machineEventClose},
			wantState:  machineStateCompleted,
			wantAction: machineActionNone,
		},
		{
			name:       "terminal event before send is invalid",
			events:     []machineEvent{machineEventInboundSimpleACK},
			wantState:  machineStateIdle,
			wantAction: machineActionNone,
			wantErr:    ErrInvalidStateTransition,
		},
		{
			name:       "confirmed request event in idle is invalid",
			events:     []machineEvent{machineEventSendConfirmedRequest},
			wantState:  machineStateIdle,
			wantAction: machineActionNone,
			wantErr:    ErrInvalidStateTransition,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			machine := newUnconfirmedClientMachine()
			var gotOutput machineOutput
			var err error

			for _, event := range tt.events {
				input := machineInput{}
				if event == machineEventSendUnconfirmedRequest {
					input.UnconfirmedRequest = &UnconfirmedRequest{ServiceChoice: ServiceChoiceWhoIs, Payload: []byte{0x01}}
				}
				gotOutput, err = machine.Handle(event, input)
				if err != nil {
					break
				}
			}

			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("Handle() error = %v, want %v", err, tt.wantErr)
			}
			if machine.State() != tt.wantState {
				t.Fatalf("State() = %v, want %v", machine.State(), tt.wantState)
			}
			if gotOutput.action != tt.wantAction {
				t.Fatalf("action = %v, want %v", gotOutput.action, tt.wantAction)
			}
		})
	}
}

func TestUnconfirmedServerMachineTransitions(t *testing.T) {
	tests := []struct {
		name       string
		events     []machineEvent
		wantState  machineState
		wantAction machineAction
		wantErr    error
	}{
		{
			name:       "receive then handler done completes",
			events:     []machineEvent{machineEventInboundUnconfirmedRequest, machineEventHandlerDone},
			wantState:  machineStateCompleted,
			wantAction: machineActionNone,
		},
		{
			name:       "receive then handler error aborts",
			events:     []machineEvent{machineEventInboundUnconfirmedRequest, machineEventHandlerError},
			wantState:  machineStateAborted,
			wantAction: machineActionNone,
		},
		{
			name:       "receive then close aborts with fail-closed action",
			events:     []machineEvent{machineEventInboundUnconfirmedRequest, machineEventClose},
			wantState:  machineStateAborted,
			wantAction: machineActionFailClosed,
		},
		{
			name:       "close in completed state is noop",
			events:     []machineEvent{machineEventInboundUnconfirmedRequest, machineEventHandlerDone, machineEventClose},
			wantState:  machineStateCompleted,
			wantAction: machineActionNone,
		},
		{
			name:       "close in aborted state is noop",
			events:     []machineEvent{machineEventInboundUnconfirmedRequest, machineEventHandlerError, machineEventClose},
			wantState:  machineStateAborted,
			wantAction: machineActionNone,
		},
		{
			name:       "handler event before receive is invalid",
			events:     []machineEvent{machineEventHandlerDone},
			wantState:  machineStateIdle,
			wantAction: machineActionNone,
			wantErr:    ErrInvalidStateTransition,
		},
		{
			name:       "confirmed request event in idle is invalid",
			events:     []machineEvent{machineEventInboundConfirmedRequest},
			wantState:  machineStateIdle,
			wantAction: machineActionNone,
			wantErr:    ErrInvalidStateTransition,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			machine := newUnconfirmedServerMachine()
			var gotOutput machineOutput
			var err error

			for _, event := range tt.events {
				gotOutput, err = machine.Handle(event, machineInput{})
				if err != nil {
					break
				}
			}

			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("Handle() error = %v, want %v", err, tt.wantErr)
			}
			if machine.State() != tt.wantState {
				t.Fatalf("State() = %v, want %v", machine.State(), tt.wantState)
			}
			if gotOutput.action != tt.wantAction {
				t.Fatalf("action = %v, want %v", gotOutput.action, tt.wantAction)
			}
		})
	}
}

func TestNewUnconfirmedClientMachineWithConfigInitializesVariables(t *testing.T) {
	machine := newUnconfirmedClientMachineWithConfig(unconfirmedClientMachineConfig{
		requestPayloadLength: 20,
	})

	if machine.State() != machineStateIdle {
		t.Fatalf("State() = %v, want %v", machine.State(), machineStateIdle)
	}
	if machine.Role() != machineRoleUnconfirmedClient {
		t.Fatalf("Role() = %v, want %v", machine.Role(), machineRoleUnconfirmedClient)
	}
	if machine.variables.requestPayloadLength != 20 {
		t.Fatalf("requestPayloadLength = %d, want 20", machine.variables.requestPayloadLength)
	}
}

func TestNewUnconfirmedServerMachineWithConfigInitializesVariables(t *testing.T) {
	machine := newUnconfirmedServerMachineWithConfig(unconfirmedServerMachineConfig{
		requestPayloadLength: 42,
	})

	if machine.State() != machineStateIdle {
		t.Fatalf("State() = %v, want %v", machine.State(), machineStateIdle)
	}
	if machine.Role() != machineRoleUnconfirmedServer {
		t.Fatalf("Role() = %v, want %v", machine.Role(), machineRoleUnconfirmedServer)
	}
	if machine.variables.requestPayloadLength != 42 {
		t.Fatalf("requestPayloadLength = %d, want 42", machine.variables.requestPayloadLength)
	}
}

func TestConfirmedClientMachineHandleReturnsErrorOnUnknownState(t *testing.T) {
	machine := newConfirmedClientMachine()
	machine.state = machineState(255)

	_, err := machine.Handle(machineEventSendConfirmedRequest, machineInput{})
	if !errors.Is(err, ErrInvalidStateTransition) {
		t.Fatalf("Handle() error = %v, want %v", err, ErrInvalidStateTransition)
	}
}

func TestUnconfirmedClientMachineHandlePanicsOnUnknownState(t *testing.T) {
	machine := newUnconfirmedClientMachine()
	machine.state = machineState(255)

	defer func() {
		if r := recover(); r == nil {
			t.Fatalf("Handle() did not panic for unknown state")
		}
	}()

	_, _ = machine.Handle(machineEventSendUnconfirmedRequest, machineInput{})
}

func TestUnconfirmedServerMachineHandleReturnsErrorOnUnknownState(t *testing.T) {
	machine := newUnconfirmedServerMachine()
	machine.state = machineState(255)

	_, err := machine.Handle(machineEventInboundUnconfirmedRequest, machineInput{})
	if !errors.Is(err, ErrInvalidStateTransition) {
		t.Fatalf("Handle() error = %v, want %v", err, ErrInvalidStateTransition)
	}
}

// TODO(5.4.x): expand segmented-response/client segmentation tests as support is implemented.

// ---------------------------------------------------------------------------
// Segmented server machine tests (§5.4.5)
// ---------------------------------------------------------------------------

func makeSegFirstAPDU(invokeID InvokeID, seq uint8, window uint8, moreFollows bool, serviceChoice ServiceChoice, payload []byte) inboundAPDU {
	return inboundAPDU{
		Type:               PDUTypeConfirmedRequest,
		SegmentedMessage:   true,
		MoreFollows:        moreFollows,
		SequenceNumber:     seq,
		ProposedWindowSize: window,
		InvokeID:           invokeID,
		ServiceChoice:      serviceChoice,
		Payload:            payload,
	}
}

func makeSegContinuationAPDU(invokeID InvokeID, seq uint8, moreFollows bool, payload []byte) inboundAPDU {
	return inboundAPDU{
		Type:             PDUTypeConfirmedRequest,
		SegmentedMessage: true,
		MoreFollows:      moreFollows,
		SequenceNumber:   seq,
		InvokeID:         invokeID,
		Payload:          payload,
	}
}

// TestSegmentedServerMachineHappyPath verifies a clean two-segment receive where
// each segment fills exactly one window slot (window=1 per segment).
func TestSegmentedServerMachineHappyPath(t *testing.T) {
	seg0 := makeSegFirstAPDU(1, 0, 1, true, ServiceChoiceReadProperty, []byte{0xAA})
	machine := newConfirmedServerMachineWithConfig(confirmedServerMachineConfig{
		invokeID:      1,
		serviceChoice: ServiceChoiceReadProperty,
		segmentation:  SegmentationSupportBoth,
	})

	// First segment → Segment-ACK for seq 0, stay in segmented-receive.
	out, err := machine.Handle(machineEventInboundConfirmedRequest, machineInput{InboundAPDU: &seg0})
	if err != nil {
		t.Fatalf("Handle(first segment) error = %v", err)
	}
	if machine.State() != machineStateSegmentedRequestReceiving {
		t.Fatalf("state = %v, want segmented-request-receiving", machine.State())
	}
	if out.action != machineActionSendSegmentACK {
		t.Fatalf("action = %v, want send-segment-ack", out.action)
	}
	if out.OutboundAPDU == nil || out.OutboundAPDU.NegativeAck {
		t.Fatal("expected positive Segment-ACK outbound APDU")
	}
	if out.OutboundAPDU.SequenceNumber != 0 {
		t.Fatalf("Segment-ACK seqNum = %d, want 0", out.OutboundAPDU.SequenceNumber)
	}

	// Second (last) segment → Segment-ACK for seq 1, transition to await-response.
	seg1 := makeSegContinuationAPDU(1, 1, false, []byte{0xBB})
	out, err = machine.Handle(machineEventInboundSegment, machineInput{InboundAPDU: &seg1})
	if err != nil {
		t.Fatalf("Handle(last segment) error = %v", err)
	}
	if machine.State() != machineStateAwaitResponse {
		t.Fatalf("state = %v, want await-response", machine.State())
	}
	if out.action != machineActionSendSegmentACK {
		t.Fatalf("action = %v, want send-segment-ack", out.action)
	}
	if out.OutboundAPDU.NegativeAck {
		t.Fatal("expected positive Segment-ACK on last segment")
	}
	if out.OutboundAPDU.SequenceNumber != 1 {
		t.Fatalf("Segment-ACK seqNum = %d, want 1", out.OutboundAPDU.SequenceNumber)
	}

	// Verify assembled payload.
	assembled := machine.AssembledPayload()
	if len(assembled) != 2 || assembled[0] != 0xAA || assembled[1] != 0xBB {
		t.Fatalf("assembled payload = %v, want [0xAA 0xBB]", assembled)
	}
}

// TestSegmentedServerMachineWindowOfTwo verifies that within a window of two
// segments, the Segment-ACK is only sent at the end of the window.
func TestSegmentedServerMachineWindowOfTwo(t *testing.T) {
	seg0 := makeSegFirstAPDU(2, 0, 2, true, ServiceChoiceReadProperty, []byte{0x01})
	machine := newConfirmedServerMachineWithConfig(confirmedServerMachineConfig{
		invokeID:            2,
		serviceChoice:       ServiceChoiceReadProperty,
		segmentation:        SegmentationSupportBoth,
		preferredWindowSize: 2,
	})

	// First segment in window-2; no ACK yet (mid-window).
	out, err := machine.Handle(machineEventInboundConfirmedRequest, machineInput{InboundAPDU: &seg0})
	if err != nil {
		t.Fatalf("Handle(seg0) error = %v", err)
	}
	if machine.State() != machineStateSegmentedRequestReceiving {
		t.Fatalf("state = %v after seg0", machine.State())
	}
	if out.action != machineActionNone {
		t.Fatalf("action = %v after seg0 (mid-window), want none", out.action)
	}

	// Second segment fills the window → Segment-ACK.
	seg1 := makeSegContinuationAPDU(2, 1, true, []byte{0x02})
	out, err = machine.Handle(machineEventInboundSegment, machineInput{InboundAPDU: &seg1})
	if err != nil {
		t.Fatalf("Handle(seg1) error = %v", err)
	}
	if machine.State() != machineStateSegmentedRequestReceiving {
		t.Fatalf("state = %v after seg1 (not last)", machine.State())
	}
	if out.action != machineActionSendSegmentACK {
		t.Fatalf("action = %v after end-of-window, want send-segment-ack", out.action)
	}
	if out.OutboundAPDU == nil || out.OutboundAPDU.ActualWindowSize != 2 {
		t.Fatalf("Segment-ACK window size = %v, want 2", out.OutboundAPDU)
	}

	// Third (last) segment → Segment-ACK + await-response.
	seg2 := makeSegContinuationAPDU(2, 2, false, []byte{0x03})
	out, err = machine.Handle(machineEventInboundSegment, machineInput{InboundAPDU: &seg2})
	if err != nil {
		t.Fatalf("Handle(seg2) error = %v", err)
	}
	if machine.State() != machineStateAwaitResponse {
		t.Fatalf("state = %v after last segment, want await-response", machine.State())
	}
	if out.action != machineActionSendSegmentACK {
		t.Fatalf("action = %v after last segment, want send-segment-ack", out.action)
	}

	assembled := machine.AssembledPayload()
	if len(assembled) != 3 || assembled[0] != 0x01 || assembled[1] != 0x02 || assembled[2] != 0x03 {
		t.Fatalf("assembled = %v, want [0x01 0x02 0x03]", assembled)
	}
}

func TestSegmentedServerMachineNegotiatesWindowSize(t *testing.T) {
	machine := newConfirmedServerMachineWithConfig(confirmedServerMachineConfig{
		invokeID:            6,
		serviceChoice:       ServiceChoiceReadProperty,
		segmentation:        SegmentationSupportBoth,
		preferredWindowSize: 2,
	})

	seg0 := makeSegFirstAPDU(6, 0, 5, true, ServiceChoiceReadProperty, []byte{0x01})
	out, err := machine.Handle(machineEventInboundConfirmedRequest, machineInput{InboundAPDU: &seg0})
	if err != nil {
		t.Fatalf("Handle(seg0) error = %v", err)
	}
	if out.action != machineActionNone {
		t.Fatalf("action = %v, want none until negotiated window fills", out.action)
	}

	seg1 := makeSegContinuationAPDU(6, 1, true, []byte{0x02})
	out, err = machine.Handle(machineEventInboundSegment, machineInput{InboundAPDU: &seg1})
	if err != nil {
		t.Fatalf("Handle(seg1) error = %v", err)
	}
	if out.action != machineActionSendSegmentACK {
		t.Fatalf("action = %v, want send-segment-ack", out.action)
	}
	if out.OutboundAPDU == nil {
		t.Fatal("OutboundAPDU is nil, want Segment-ACK")
	}
	if out.OutboundAPDU.ActualWindowSize != 2 {
		t.Fatalf("ActualWindowSize = %d, want 2", out.OutboundAPDU.ActualWindowSize)
	}
}

func TestSegmentedServerMachineUnsupportedSegmentationSendsAbort(t *testing.T) {
	machine := newConfirmedServerMachineWithConfig(confirmedServerMachineConfig{
		invokeID:            7,
		serviceChoice:       ServiceChoiceReadProperty,
		segmentation:        SegmentationSupportNo,
		preferredWindowSize: 1,
	})

	seg0 := makeSegFirstAPDU(7, 0, 1, true, ServiceChoiceReadProperty, []byte{0xAA})
	out, err := machine.Handle(machineEventInboundConfirmedRequest, machineInput{InboundAPDU: &seg0})
	if err != nil {
		t.Fatalf("Handle(seg0) error = %v", err)
	}
	if machine.State() != machineStateAborted {
		t.Fatalf("state = %v, want aborted", machine.State())
	}
	if out.action != machineActionSendAbort {
		t.Fatalf("action = %v, want send-abort", out.action)
	}
	if out.OutboundAPDU == nil || out.OutboundAPDU.Type != PDUTypeAbort {
		t.Fatalf("OutboundAPDU = %#v, want abort", out.OutboundAPDU)
	}
}

// TestSegmentedServerMachineOutOfOrder verifies that an out-of-order segment
// is NAKed immediately and must be retransmitted after the gap is filled.
func TestSegmentedServerMachineOutOfOrder(t *testing.T) {
	seg0 := makeSegFirstAPDU(3, 0, 2, true, ServiceChoiceReadProperty, []byte{0xAA})
	machine := newConfirmedServerMachineWithConfig(confirmedServerMachineConfig{
		invokeID:            3,
		serviceChoice:       ServiceChoiceReadProperty,
		segmentation:        SegmentationSupportBoth,
		preferredWindowSize: 2,
	})

	if _, err := machine.Handle(machineEventInboundConfirmedRequest, machineInput{InboundAPDU: &seg0}); err != nil {
		t.Fatalf("Handle(seg0) error = %v", err)
	}

	// Send seq=2 before seq=1. The gap is NAKed immediately.
	badSeg := makeSegContinuationAPDU(3, 2, false, []byte{0xCC})
	out, err := machine.Handle(machineEventInboundSegment, machineInput{InboundAPDU: &badSeg})
	if err != nil {
		t.Fatalf("Handle(out-of-order) error = %v", err)
	}
	if machine.State() != machineStateSegmentedRequestReceiving {
		t.Fatalf("state = %v, want segmented-request-receiving", machine.State())
	}

	if out.action != machineActionSendSegmentACK {
		t.Fatalf("action = %v, want send-segment-ack", out.action)
	}

	if out.OutboundAPDU == nil || !out.OutboundAPDU.NegativeAck {
		t.Fatal("expected negative Segment-ACK for out-of-order segment")
	}

	if out.OutboundAPDU.SequenceNumber != 0 {
		t.Fatalf("Segment-ACK seqNum = %d, want 0", out.OutboundAPDU.SequenceNumber)
	}

	// Missing seq=1 arrives and is ACKed as normal progress.
	seg1 := makeSegContinuationAPDU(3, 1, true, []byte{0xBB})
	out, err = machine.Handle(machineEventInboundSegment, machineInput{InboundAPDU: &seg1})
	if err != nil {
		t.Fatalf("Handle(seq1) error = %v", err)
	}

	if machine.State() != machineStateSegmentedRequestReceiving {
		t.Fatalf("state = %v, want segmented-request-receiving", machine.State())
	}

	if out.action != machineActionSendSegmentACK {
		t.Fatalf("action = %v, want send-segment-ack", out.action)
	}

	if out.OutboundAPDU == nil || out.OutboundAPDU.NegativeAck {
		t.Fatal("expected positive Segment-ACK after receiving missing sequence")
	}

	if out.OutboundAPDU.SequenceNumber != 1 {
		t.Fatalf("Segment-ACK seqNum = %d, want 1", out.OutboundAPDU.SequenceNumber)
	}

	// Sender retransmits seq=2 after NAK; this completes the transaction.
	seg2 := makeSegContinuationAPDU(3, 2, false, []byte{0xCC})
	out, err = machine.Handle(machineEventInboundSegment, machineInput{InboundAPDU: &seg2})
	if err != nil {
		t.Fatalf("Handle(retransmitted seq2) error = %v", err)
	}
	if machine.State() != machineStateAwaitResponse {
		t.Fatalf("state = %v, want await-response", machine.State())
	}
	if out.action != machineActionSendSegmentACK {
		t.Fatalf("action = %v, want send-segment-ack", out.action)
	}
	if out.OutboundAPDU == nil || out.OutboundAPDU.NegativeAck {
		t.Fatal("expected positive Segment-ACK after retransmitted segment")
	}
	if out.OutboundAPDU.SequenceNumber != 2 {
		t.Fatalf("Segment-ACK seqNum = %d, want 2", out.OutboundAPDU.SequenceNumber)
	}

	assembled := machine.AssembledPayload()
	if len(assembled) != 3 || assembled[0] != 0xAA || assembled[1] != 0xBB || assembled[2] != 0xCC {
		t.Fatalf("assembled = %v, want [0xAA 0xBB 0xCC]", assembled)
	}
}

func TestSegmentedServerMachineDuplicateFirstSegmentReACKsLastContiguous(t *testing.T) {
	seg0 := makeSegFirstAPDU(11, 0, 1, true, ServiceChoiceReadProperty, []byte{0xAA})
	machine := newConfirmedServerMachineWithConfig(confirmedServerMachineConfig{
		invokeID:      11,
		serviceChoice: ServiceChoiceReadProperty,
		segmentation:  SegmentationSupportBoth,
	})

	if _, err := machine.Handle(machineEventInboundConfirmedRequest, machineInput{InboundAPDU: &seg0}); err != nil {
		t.Fatalf("Handle(seg0) error = %v", err)
	}

	dupOut, err := machine.Handle(machineEventInboundConfirmedRequest, machineInput{InboundAPDU: &seg0})
	if err != nil {
		t.Fatalf("Handle(duplicate seg0) error = %v", err)
	}

	if machine.State() != machineStateSegmentedRequestReceiving {
		t.Fatalf("state = %v, want segmented-request-receiving", machine.State())
	}

	if dupOut.action != machineActionSendSegmentACK {
		t.Fatalf("action = %v, want send-segment-ack", dupOut.action)
	}

	if dupOut.OutboundAPDU == nil || dupOut.OutboundAPDU.NegativeAck {
		t.Fatalf("OutboundAPDU = %#v, want positive Segment-ACK", dupOut.OutboundAPDU)
	}

	if dupOut.OutboundAPDU.SequenceNumber != 0 {
		t.Fatalf("Segment-ACK seqNum = %d, want 0", dupOut.OutboundAPDU.SequenceNumber)
	}

	if machine.variables.segmented.duplicateCount != 1 {
		t.Fatalf("duplicateCount = %d, want 1", machine.variables.segmented.duplicateCount)
	}
}

func TestSegmentedServerMachineDuplicateCountResetsOnProgress(t *testing.T) {
	seg0 := makeSegFirstAPDU(12, 0, 1, true, ServiceChoiceReadProperty, []byte{0xAA})
	machine := newConfirmedServerMachineWithConfig(confirmedServerMachineConfig{
		invokeID:      12,
		serviceChoice: ServiceChoiceReadProperty,
		segmentation:  SegmentationSupportBoth,
	})

	if _, err := machine.Handle(machineEventInboundConfirmedRequest, machineInput{InboundAPDU: &seg0}); err != nil {
		t.Fatalf("Handle(seg0) error = %v", err)
	}

	if _, err := machine.Handle(machineEventInboundConfirmedRequest, machineInput{InboundAPDU: &seg0}); err != nil {
		t.Fatalf("Handle(duplicate seg0) error = %v", err)
	}

	if machine.variables.segmented.duplicateCount != 1 {
		t.Fatalf("duplicateCount = %d, want 1 before progress", machine.variables.segmented.duplicateCount)
	}

	seg1 := makeSegContinuationAPDU(12, 1, false, []byte{0xBB})
	if _, err := machine.Handle(machineEventInboundSegment, machineInput{InboundAPDU: &seg1}); err != nil {
		t.Fatalf("Handle(seg1) error = %v", err)
	}

	if machine.variables.segmented.duplicateCount != 0 {
		t.Fatalf("duplicateCount = %d, want 0 after progress", machine.variables.segmented.duplicateCount)
	}
}

func TestSegmentedServerMachineExceedingMaxDuplicatesSendsAbort(t *testing.T) {
	seg0 := makeSegFirstAPDU(13, 0, 1, true, ServiceChoiceReadProperty, []byte{0xAA})
	machine := newConfirmedServerMachineWithConfig(confirmedServerMachineConfig{
		invokeID:             13,
		serviceChoice:        ServiceChoiceReadProperty,
		segmentation:         SegmentationSupportBoth,
		maxSegmentDuplicates: 1,
	})

	if _, err := machine.Handle(machineEventInboundConfirmedRequest, machineInput{InboundAPDU: &seg0}); err != nil {
		t.Fatalf("Handle(seg0) error = %v", err)
	}
	if _, err := machine.Handle(machineEventInboundConfirmedRequest, machineInput{InboundAPDU: &seg0}); err != nil {
		t.Fatalf("first duplicate error = %v", err)
	}

	out, err := machine.Handle(machineEventInboundConfirmedRequest, machineInput{InboundAPDU: &seg0})
	if err != nil {
		t.Fatalf("second duplicate error = %v", err)
	}

	if machine.State() != machineStateAborted {
		t.Fatalf("state = %v, want aborted", machine.State())
	}

	if out.action != machineActionSendAbort {
		t.Fatalf("action = %v, want send-abort", out.action)
	}

	if out.OutboundAPDU == nil || out.OutboundAPDU.Type != PDUTypeAbort {
		t.Fatalf("OutboundAPDU = %#v, want Abort", out.OutboundAPDU)
	}
}

func TestSegmentedServerMachineRejectsFirstSegmentWithoutSeqZero(t *testing.T) {
	machine := newConfirmedServerMachineWithConfig(confirmedServerMachineConfig{
		invokeID:      10,
		serviceChoice: ServiceChoiceReadProperty,
		segmentation:  SegmentationSupportBoth,
	})

	badFirst := makeSegFirstAPDU(10, 1, 1, true, ServiceChoiceReadProperty, []byte{0xAA})
	out, err := machine.Handle(machineEventInboundConfirmedRequest, machineInput{InboundAPDU: &badFirst})
	if err != nil {
		t.Fatalf("Handle(bad first segment) error = %v", err)
	}
	if machine.State() != machineStateAborted {
		t.Fatalf("state = %v, want aborted", machine.State())
	}
	if out.action != machineActionSendAbort {
		t.Fatalf("action = %v, want send-abort", out.action)
	}
	if out.OutboundAPDU == nil || out.OutboundAPDU.Type != PDUTypeAbort {
		t.Fatalf("OutboundAPDU = %#v, want abort", out.OutboundAPDU)
	}
}

// TestSegmentedServerMachineAbortFromPeer verifies that an inbound Abort PDU
// transitions the machine to aborted from segmented-request-receiving.
func TestSegmentedServerMachineAbortFromPeer(t *testing.T) {
	seg0 := makeSegFirstAPDU(4, 0, 1, true, ServiceChoiceReadProperty, []byte{0xAA})
	machine := newConfirmedServerMachineWithConfig(confirmedServerMachineConfig{
		invokeID:      4,
		serviceChoice: ServiceChoiceReadProperty,
		segmentation:  SegmentationSupportBoth,
	})
	if _, err := machine.Handle(machineEventInboundConfirmedRequest, machineInput{InboundAPDU: &seg0}); err != nil {
		t.Fatalf("Handle(seg0) error = %v", err)
	}

	out, err := machine.Handle(machineEventInboundAbort, machineInput{})
	if err != nil {
		t.Fatalf("Handle(abort) error = %v", err)
	}
	if machine.State() != machineStateAborted {
		t.Fatalf("state = %v, want aborted", machine.State())
	}
	if out.action != machineActionNone {
		t.Fatalf("action = %v, want none", out.action)
	}
}

// TestSegmentedServerMachineSingleSegmentIsDispatched verifies that a "segmented"
// request with MoreFollows=false in the first packet is treated as complete and
// transitions directly to await-response.
func TestSegmentedServerMachineSingleSegmentIsDispatched(t *testing.T) {
	seg0 := makeSegFirstAPDU(5, 0, 1, false, ServiceChoiceReadProperty, []byte{0xAA, 0xBB})
	machine := newConfirmedServerMachineWithConfig(confirmedServerMachineConfig{
		invokeID:      5,
		serviceChoice: ServiceChoiceReadProperty,
		segmentation:  SegmentationSupportBoth,
	})

	out, err := machine.Handle(machineEventInboundConfirmedRequest, machineInput{InboundAPDU: &seg0})
	if err != nil {
		t.Fatalf("Handle(single-segment) error = %v", err)
	}
	if machine.State() != machineStateAwaitResponse {
		t.Fatalf("state = %v, want await-response", machine.State())
	}
	if out.action != machineActionSendSegmentACK {
		t.Fatalf("action = %v, want send-segment-ack", out.action)
	}
	assembled := machine.AssembledPayload()
	if len(assembled) != 2 || assembled[0] != 0xAA || assembled[1] != 0xBB {
		t.Fatalf("assembled = %v, want [0xAA 0xBB]", assembled)
	}
}

func TestSegmentedServerMachineSegmentTimeoutSendsAbort(t *testing.T) {
	seg0 := makeSegFirstAPDU(8, 0, 1, true, ServiceChoiceReadProperty, []byte{0xAA})
	machine := newConfirmedServerMachineWithConfig(confirmedServerMachineConfig{
		invokeID:      8,
		serviceChoice: ServiceChoiceReadProperty,
		segmentation:  SegmentationSupportBoth,
	})

	if _, err := machine.Handle(machineEventInboundConfirmedRequest, machineInput{InboundAPDU: &seg0}); err != nil {
		t.Fatalf("Handle(seg0) error = %v", err)
	}

	out, err := machine.Handle(machineEventSegmentTimeout, machineInput{Cause: ErrAPDUTimeout})
	if err != nil {
		t.Fatalf("Handle(segment-timeout) error = %v", err)
	}
	if machine.State() != machineStateAborted {
		t.Fatalf("state = %v, want aborted", machine.State())
	}
	if out.action != machineActionSendAbort {
		t.Fatalf("action = %v, want send-abort", out.action)
	}
	if out.OutboundAPDU == nil || out.OutboundAPDU.Type != PDUTypeAbort {
		t.Fatalf("OutboundAPDU = %#v, want Abort", out.OutboundAPDU)
	}
}

func TestConfirmedServerMachineStartsSegmentedComplexACKResponse(t *testing.T) {
	machine := newConfirmedServerMachineWithConfig(confirmedServerMachineConfig{
		invokeID:                     30,
		serviceChoice:                ServiceChoiceReadProperty,
		requesterSegmentation:        SegmentationSupportReceive,
		requesterMaxSegmentsAccepted: MaxSegments4,
		requesterMaxAPDUSizeAccepted: 50,
		segmentation:                 SegmentationSupportBoth,
		maxRetries:                   1,
		maxAPDUSizeAccepted:          50,
	})

	if _, err := machine.Handle(machineEventInboundConfirmedRequest, machineInput{}); err != nil {
		t.Fatalf("setup Handle() error: %v", err)
	}

	payload := make([]byte, 60)
	for i := range payload {
		payload[i] = byte(i)
	}

	ackType := ConfirmedResponseTypeACK
	out, err := machine.Handle(machineEventResponseRequiresSegmentation, machineInput{
		HandlerResult:       &ServiceResult{Payload: payload},
		HandlerResponseType: &ackType,
	})
	if err != nil {
		t.Fatalf("Handle(response-requires-segmentation) error = %v", err)
	}
	if machine.State() != machineStateAwaitSegmentACK {
		t.Fatalf("State() = %v, want %v", machine.State(), machineStateAwaitSegmentACK)
	}
	if out.action != machineActionSendComplexACK {
		t.Fatalf("action = %v, want %v", out.action, machineActionSendComplexACK)
	}
	if out.OutboundAPDU == nil {
		t.Fatal("OutboundAPDU is nil, want segmented ComplexACK")
	}
	if out.OutboundAPDU.Type != PDUTypeComplexACK || !out.OutboundAPDU.SegmentedMessage {
		t.Fatalf("OutboundAPDU = %#v, want segmented ComplexACK", out.OutboundAPDU)
	}
	if !out.OutboundAPDU.MoreFollows {
		t.Fatal("MoreFollows = false, want true on first segment")
	}
	if out.OutboundAPDU.SequenceNumber != 0 {
		t.Fatalf("SequenceNumber = %d, want 0", out.OutboundAPDU.SequenceNumber)
	}
	if len(out.OutboundAPDU.Payload) != 45 {
		t.Fatalf("payload length = %d, want 45", len(out.OutboundAPDU.Payload))
	}
}

func TestConfirmedServerMachineStartsSegmentedComplexACKResponseWithWindow(t *testing.T) {
	machine := newConfirmedServerMachineWithConfig(confirmedServerMachineConfig{
		invokeID:                     33,
		serviceChoice:                ServiceChoiceReadProperty,
		requesterSegmentation:        SegmentationSupportReceive,
		requesterMaxSegmentsAccepted: MaxSegments4,
		requesterMaxAPDUSizeAccepted: 50,
		segmentation:                 SegmentationSupportBoth,
		preferredWindowSize:          2,
		maxRetries:                   1,
		maxAPDUSizeAccepted:          50,
	})

	if _, err := machine.Handle(machineEventInboundConfirmedRequest, machineInput{}); err != nil {
		t.Fatalf("setup Handle() error: %v", err)
	}

	payload := make([]byte, 120)
	for i := range payload {
		payload[i] = byte(i)
	}

	out, err := machine.Handle(machineEventResponseRequiresSegmentation, machineInput{
		HandlerResult:       ptr(ServiceResult{Payload: payload}),
		HandlerResponseType: ptr(ConfirmedResponseTypeACK),
	})
	if err != nil {
		t.Fatalf("Handle(response-requires-segmentation) error = %v", err)
	}

	if machine.State() != machineStateAwaitSegmentACK {
		t.Fatalf("State() = %v, want %v", machine.State(), machineStateAwaitSegmentACK)
	}

	if out.action != machineActionSendComplexACK {
		t.Fatalf("action = %v, want %v", out.action, machineActionSendComplexACK)
	}

	if len(out.OutboundAPDUs) != 2 {
		t.Fatalf("len(OutboundAPDUs) = %d, want 2", len(out.OutboundAPDUs))
	}

	if out.OutboundAPDUs[0].SequenceNumber != 0 || out.OutboundAPDUs[1].SequenceNumber != 1 {
		t.Fatalf("window sequences = [%d %d], want [0 1]", out.OutboundAPDUs[0].SequenceNumber, out.OutboundAPDUs[1].SequenceNumber)
	}

	if !out.OutboundAPDUs[0].MoreFollows || !out.OutboundAPDUs[1].MoreFollows {
		t.Fatal("first transmit window must set MoreFollows=true for both segments")
	}

	out, err = machine.Handle(machineEventInboundSegmentACK, machineInput{InboundAPDU: &inboundAPDU{Type: PDUTypeSegmentACK, InvokeID: 33, SequenceNumber: 1, ActualWindowSize: 2}})
	if err != nil {
		t.Fatalf("Handle(window SegmentACK) error = %v", err)
	}

	if out.action != machineActionSendComplexACK {
		t.Fatalf("action = %v, want %v", out.action, machineActionSendComplexACK)
	}

	if len(out.OutboundAPDUs) != 1 {
		t.Fatalf("len(OutboundAPDUs) = %d, want 1", len(out.OutboundAPDUs))
	}

	if out.OutboundAPDUs[0].SequenceNumber != 2 {
		t.Fatalf("final window sequence = %d, want 2", out.OutboundAPDUs[0].SequenceNumber)
	}

	if out.OutboundAPDUs[0].MoreFollows {
		t.Fatal("final segment MoreFollows = true, want false")
	}

	out, err = machine.Handle(machineEventInboundSegmentACK, machineInput{InboundAPDU: &inboundAPDU{Type: PDUTypeSegmentACK, InvokeID: 33, SequenceNumber: 2, ActualWindowSize: 2}})
	if err != nil {
		t.Fatalf("Handle(final SegmentACK) error = %v", err)
	}

	if machine.State() != machineStateCompleted {
		t.Fatalf("State() = %v, want %v", machine.State(), machineStateCompleted)
	}

	if out.action != machineActionNone {
		t.Fatalf("action = %v, want %v", out.action, machineActionNone)
	}
}

func TestConfirmedServerMachineSegmentedComplexACKNegativeAckRetransmitsCurrentWindow(t *testing.T) {
	machine := newConfirmedServerMachineWithConfig(confirmedServerMachineConfig{
		invokeID:                     34,
		serviceChoice:                ServiceChoiceReadProperty,
		requesterSegmentation:        SegmentationSupportReceive,
		requesterMaxSegmentsAccepted: MaxSegments4,
		requesterMaxAPDUSizeAccepted: 50,
		segmentation:                 SegmentationSupportBoth,
		preferredWindowSize:          2,
		maxRetries:                   1,
		maxAPDUSizeAccepted:          50,
	})

	if _, err := machine.Handle(machineEventInboundConfirmedRequest, machineInput{}); err != nil {
		t.Fatalf("setup Handle() error: %v", err)
	}

	payload := make([]byte, 120)
	if _, err := machine.Handle(machineEventResponseRequiresSegmentation, machineInput{
		HandlerResult:       ptr(ServiceResult{Payload: payload}),
		HandlerResponseType: ptr(ConfirmedResponseTypeACK),
	}); err != nil {
		t.Fatalf("Handle(response-requires-segmentation) error = %v", err)
	}

	out, err := machine.Handle(machineEventInboundSegmentACK, machineInput{InboundAPDU: &inboundAPDU{Type: PDUTypeSegmentACK, InvokeID: 34, SequenceNumber: 0, ActualWindowSize: 2, NegativeAck: true}})
	if err != nil {
		t.Fatalf("Handle(negative SegmentACK) error = %v", err)
	}

	if out.action != machineActionSendComplexACK {
		t.Fatalf("action = %v, want %v", out.action, machineActionSendComplexACK)
	}

	if len(out.OutboundAPDUs) != 2 {
		t.Fatalf("len(OutboundAPDUs) = %d, want 2", len(out.OutboundAPDUs))
	}

	if out.OutboundAPDUs[0].SequenceNumber != 0 || out.OutboundAPDUs[1].SequenceNumber != 1 {
		t.Fatalf("retransmit window sequences = [%d %d], want [0 1]", out.OutboundAPDUs[0].SequenceNumber, out.OutboundAPDUs[1].SequenceNumber)
	}
}

func TestConfirmedServerMachineSegmentedComplexACKCompletesAfterFinalSegmentACK(t *testing.T) {
	machine := newConfirmedServerMachineWithConfig(confirmedServerMachineConfig{
		invokeID:                     31,
		serviceChoice:                ServiceChoiceReadProperty,
		requesterSegmentation:        SegmentationSupportReceive,
		requesterMaxSegmentsAccepted: MaxSegments4,
		requesterMaxAPDUSizeAccepted: 50,
		segmentation:                 SegmentationSupportBoth,
		maxRetries:                   1,
		maxAPDUSizeAccepted:          50,
	})

	if _, err := machine.Handle(machineEventInboundConfirmedRequest, machineInput{}); err != nil {
		t.Fatalf("setup Handle() error: %v", err)
	}

	payload := make([]byte, 60)
	for i := range payload {
		payload[i] = byte(i)
	}
	ackType := ConfirmedResponseTypeACK
	if _, err := machine.Handle(machineEventResponseRequiresSegmentation, machineInput{
		HandlerResult:       &ServiceResult{Payload: payload},
		HandlerResponseType: &ackType,
	}); err != nil {
		t.Fatalf("Handle(response-requires-segmentation) error = %v", err)
	}

	out, err := machine.Handle(machineEventInboundSegmentACK, machineInput{InboundAPDU: &inboundAPDU{Type: PDUTypeSegmentACK, InvokeID: 31, SequenceNumber: 0, ActualWindowSize: 1}})
	if err != nil {
		t.Fatalf("Handle(first segment-ack) error = %v", err)
	}
	if machine.State() != machineStateAwaitSegmentACK {
		t.Fatalf("State() = %v, want %v after first ack", machine.State(), machineStateAwaitSegmentACK)
	}
	if out.OutboundAPDU == nil || out.OutboundAPDU.SequenceNumber != 1 {
		t.Fatalf("OutboundAPDU = %#v, want second segmented ComplexACK", out.OutboundAPDU)
	}
	if out.OutboundAPDU.MoreFollows {
		t.Fatal("MoreFollows = true, want false on final segment")
	}
	if len(out.OutboundAPDU.Payload) != 15 {
		t.Fatalf("payload length = %d, want 15", len(out.OutboundAPDU.Payload))
	}

	out, err = machine.Handle(machineEventInboundSegmentACK, machineInput{InboundAPDU: &inboundAPDU{Type: PDUTypeSegmentACK, InvokeID: 31, SequenceNumber: 1, ActualWindowSize: 1}})
	if err != nil {
		t.Fatalf("Handle(final segment-ack) error = %v", err)
	}
	if machine.State() != machineStateCompleted {
		t.Fatalf("State() = %v, want %v", machine.State(), machineStateCompleted)
	}
	if out.action != machineActionNone || out.OutboundAPDU != nil {
		t.Fatalf("final output = %#v, want no outbound APDU", out)
	}
}

func TestConfirmedServerMachineSegmentedComplexACKTimeoutRetriesThenAborts(t *testing.T) {
	machine := newConfirmedServerMachineWithConfig(confirmedServerMachineConfig{
		invokeID:                     32,
		serviceChoice:                ServiceChoiceReadProperty,
		requesterSegmentation:        SegmentationSupportReceive,
		requesterMaxSegmentsAccepted: MaxSegments4,
		requesterMaxAPDUSizeAccepted: 50,
		segmentation:                 SegmentationSupportBoth,
		maxRetries:                   1,
		maxAPDUSizeAccepted:          50,
	})

	if _, err := machine.Handle(machineEventInboundConfirmedRequest, machineInput{}); err != nil {
		t.Fatalf("setup Handle() error: %v", err)
	}

	payload := make([]byte, 60)
	ackType := ConfirmedResponseTypeACK
	if _, err := machine.Handle(machineEventResponseRequiresSegmentation, machineInput{
		HandlerResult:       &ServiceResult{Payload: payload},
		HandlerResponseType: &ackType,
	}); err != nil {
		t.Fatalf("Handle(response-requires-segmentation) error = %v", err)
	}

	out, err := machine.Handle(machineEventTimeout, machineInput{})
	if err != nil {
		t.Fatalf("first Handle(timeout) error = %v", err)
	}
	if out.action != machineActionSendComplexACK {
		t.Fatalf("first timeout action = %v, want %v", out.action, machineActionSendComplexACK)
	}

	out, err = machine.Handle(machineEventTimeout, machineInput{})
	if err != nil {
		t.Fatalf("second Handle(timeout) error = %v", err)
	}
	if machine.State() != machineStateAborted {
		t.Fatalf("State() = %v, want %v", machine.State(), machineStateAborted)
	}
	if out.action != machineActionSendAbort {
		t.Fatalf("second timeout action = %v, want %v", out.action, machineActionSendAbort)
	}
}
