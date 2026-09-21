package apdu

import "fmt"

// PDUType identifies the BACnet APDU PDU type nibble.
type PDUType byte

const (
	PDUTypeConfirmedRequest   PDUType = 0
	PDUTypeUnconfirmedRequest PDUType = 1
	PDUTypeSimpleACK          PDUType = 2
	PDUTypeComplexACK         PDUType = 3
	PDUTypeSegmentACK         PDUType = 4
	PDUTypeError              PDUType = 5
	PDUTypeReject             PDUType = 6
	PDUTypeAbort              PDUType = 7
)

func (p PDUType) String() string {
	switch p {
	case PDUTypeConfirmedRequest:
		return "confirmed-request"
	case PDUTypeUnconfirmedRequest:
		return "unconfirmed-request"
	case PDUTypeSimpleACK:
		return "simple-ack"
	case PDUTypeComplexACK:
		return "complex-ack"
	case PDUTypeSegmentACK:
		return "segment-ack"
	case PDUTypeError:
		return "error"
	case PDUTypeReject:
		return "reject"
	case PDUTypeAbort:
		return "abort"
	default:
		return fmt.Sprintf("pdu-type(%d)", p)
	}
}

// InvokeID identifies a confirmed transaction.
type InvokeID byte

// ServiceChoice identifies an application service.
type ServiceChoice byte

// Unconfirmed discovery and identification service choices.
// ISO 135-2024, application-layer service-choice groups.
const (
	ServiceChoiceIAm                                ServiceChoice = 0
	ServiceChoiceIHave                              ServiceChoice = 1
	ServiceChoiceUnconfirmedCOVNotification         ServiceChoice = 2
	ServiceChoiceUnconfirmedEventNotification       ServiceChoice = 3
	ServiceChoiceUnconfirmedPrivateTransfer         ServiceChoice = 4
	ServiceChoiceUnconfirmedTextMessage             ServiceChoice = 5
	ServiceChoiceTimeSynchronization                ServiceChoice = 6
	ServiceChoiceWhoHas                             ServiceChoice = 7
	ServiceChoiceWhoIs                              ServiceChoice = 8
	ServiceChoiceUTCTimeSynchronization             ServiceChoice = 9
	ServiceChoiceWriteGroup                         ServiceChoice = 10
	ServiceChoiceUnconfirmedCOVNotificationMultiple ServiceChoice = 11

	// Confirmed COV subscription service choice.
	//
	// BACnet encodes confirmed and unconfirmed service choices in separate namespaces.
	// In this prototype both are represented by one ServiceChoice type, so the numeric
	// value collides with ServiceChoiceUnconfirmedTextMessage.

	ServiceChoiceSubscribeCOV ServiceChoice = 5
	// ServiceChoiceAcknowledgeAlarm is confirmed service choice 0.
	ServiceChoiceAcknowledgeAlarm ServiceChoice = 0
	// ServiceChoiceConfirmedCOVNotification is the confirmed notification
	// service choice. Confirmed and unconfirmed choices occupy distinct wire
	// namespaces, so its numeric value may overlap an unconfirmed choice.
	ServiceChoiceConfirmedCOVNotification ServiceChoice = 1
	// ServiceChoiceConfirmedEventNotification is confirmed service choice 2.
	ServiceChoiceConfirmedEventNotification ServiceChoice = 2

	// Confirmed object-access service choices.
	// ISO 135-2024, application-layer service-choice groups.
	ServiceChoiceReadProperty            ServiceChoice = 12
	ServiceChoiceReadPropertyConditional ServiceChoice = 13
	ServiceChoiceReadPropertyMultiple    ServiceChoice = 14
	ServiceChoiceWriteProperty           ServiceChoice = 15
	ServiceChoiceWritePropertyMultiple   ServiceChoice = 16

	// Confirmed remote-device-management service choices.
	// ISO 135-2024, application-layer service-choice groups.
	ServiceChoiceDeviceCommunicationControl ServiceChoice = 17
	ServiceChoiceConfirmedPrivateTransfer   ServiceChoice = 18
	ServiceChoiceConfirmedTextMessage       ServiceChoice = 19
	ServiceChoiceReinitializeDevice         ServiceChoice = 20

	// Confirmed virtual-terminal and security service choices.
	// ISO 135-2024, application-layer service-choice groups.
	ServiceChoiceVTOpen       ServiceChoice = 21
	ServiceChoiceVTClose      ServiceChoice = 22
	ServiceChoiceVTData       ServiceChoice = 23
	ServiceChoiceAuthenticate ServiceChoice = 24
	ServiceChoiceRequestKey   ServiceChoice = 25

	// Confirmed alarm-event and COV service choices.
	// ISO 135-2024, application-layer service-choice groups.
	ServiceChoiceReadRange                    ServiceChoice = 26
	ServiceChoiceLifeSafetyOperation          ServiceChoice = 27
	ServiceChoiceSubscribeCOVProperty         ServiceChoice = 28
	ServiceChoiceGetEventInformation          ServiceChoice = 29
	ServiceChoiceSubscribeCOVPropertyMultiple ServiceChoice = 30
)

func (s ServiceChoice) String() string {
	switch s {
	case ServiceChoiceIAm:
		return "i-am"
	case ServiceChoiceIHave:
		return "i-have"
	case ServiceChoiceUnconfirmedCOVNotification:
		return "unconfirmed-cov-notification"
	case ServiceChoiceUnconfirmedEventNotification:
		return "unconfirmed-event-notification"
	case ServiceChoiceUnconfirmedPrivateTransfer:
		return "unconfirmed-private-transfer"
	case ServiceChoiceUnconfirmedTextMessage:
		return "unconfirmed-text-message"
	case ServiceChoiceTimeSynchronization:
		return "time-synchronization"
	case ServiceChoiceWhoHas:
		return "who-has"
	case ServiceChoiceWhoIs:
		return "who-is"
	case ServiceChoiceUTCTimeSynchronization:
		return "utc-time-synchronization"
	case ServiceChoiceWriteGroup:
		return "write-group"
	case ServiceChoiceUnconfirmedCOVNotificationMultiple:
		return "unconfirmed-cov-notification-multiple"
	case ServiceChoiceReadProperty:
		return "read-property"
	case ServiceChoiceReadPropertyConditional:
		return "read-property-conditional"
	case ServiceChoiceReadPropertyMultiple:
		return "read-property-multiple"
	case ServiceChoiceWriteProperty:
		return "write-property"
	case ServiceChoiceWritePropertyMultiple:
		return "write-property-multiple"
	case ServiceChoiceDeviceCommunicationControl:
		return "device-communication-control"
	case ServiceChoiceConfirmedPrivateTransfer:
		return "confirmed-private-transfer"
	case ServiceChoiceConfirmedTextMessage:
		return "confirmed-text-message"
	case ServiceChoiceReinitializeDevice:
		return "reinitialize-device"
	case ServiceChoiceVTOpen:
		return "vt-open"
	case ServiceChoiceVTClose:
		return "vt-close"
	case ServiceChoiceVTData:
		return "vt-data"
	case ServiceChoiceAuthenticate:
		return "authenticate"
	case ServiceChoiceRequestKey:
		return "request-key"
	case ServiceChoiceReadRange:
		return "read-range"
	case ServiceChoiceLifeSafetyOperation:
		return "life-safety-operation"
	case ServiceChoiceSubscribeCOVProperty:
		return "subscribe-cov-property"
	case ServiceChoiceGetEventInformation:
		return "get-event-information"
	case ServiceChoiceSubscribeCOVPropertyMultiple:
		return "subscribe-cov-property-multiple"
	default:
		return fmt.Sprintf("service-choice(%d)", s)
	}
}

// IsUnconfirmedServiceChoice reports whether choice is currently supported for unconfirmed requests.
func IsUnconfirmedServiceChoice(choice ServiceChoice) bool {
	switch choice {
	case ServiceChoiceIAm,
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
		ServiceChoiceUnconfirmedCOVNotificationMultiple:
		return true
	default:
		return false
	}
}

// IsConfirmedServiceChoice reports whether choice is currently supported for confirmed requests.
func IsConfirmedServiceChoice(choice ServiceChoice) bool {
	switch choice {
	case ServiceChoiceAcknowledgeAlarm,
		ServiceChoiceConfirmedCOVNotification,
		ServiceChoiceConfirmedEventNotification,
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
		ServiceChoiceSubscribeCOVPropertyMultiple:
		return true
	default:
		return false
	}
}

// ConfirmedRequest carries a confirmed service request payload.
type ConfirmedRequest struct {
	ServiceChoice ServiceChoice
	Payload       []byte
}

// UnconfirmedRequest carries an unconfirmed service request payload.
type UnconfirmedRequest struct {
	ServiceChoice ServiceChoice
	Payload       []byte
}

// ServiceResult is returned by confirmed request handlers.
type ServiceResult struct {
	Payload []byte
}

// ConfirmedAck is returned to a caller waiting on InvokeConfirmed.
type ConfirmedAck struct {
	Type          PDUType
	InvokeID      InvokeID
	ServiceChoice ServiceChoice
	Payload       []byte
}
