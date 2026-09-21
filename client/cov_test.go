package client

import (
	"context"
	"testing"
	"time"

	"github.com/worldiety/bacnet/apdu"
	"github.com/worldiety/bacnet/common/netprim"
	"github.com/worldiety/bacnet/common/types"
	"github.com/worldiety/bacnet/encoding"
)

type covAPDU struct {
	apdu.Client
	objects          []apdu.SubscribeCOVRequest
	properties       []apdu.SubscribeCOVPropertyRequest
	confirmed        apdu.ConfirmedCOVNotificationHandler
	unconfirmed      apdu.UnconfirmedCOVNotificationHandler
	acknowledgements []apdu.AcknowledgeAlarmRequest
	eventRequests    []apdu.GetEventInformationRequest
}

func (f *covAPDU) SubscribeCOV(_ context.Context, _ netprim.Address, req apdu.SubscribeCOVRequest) error {
	f.objects = append(f.objects, req)
	return nil
}
func (f *covAPDU) SubscribeCOVProperty(_ context.Context, _ netprim.Address, req apdu.SubscribeCOVPropertyRequest) error {
	f.properties = append(f.properties, req)
	return nil
}
func (f *covAPDU) HandleConfirmedCOVNotification(handler apdu.ConfirmedCOVNotificationHandler) error {
	f.confirmed = handler
	return nil
}
func (f *covAPDU) HandleUnconfirmedCOVNotification(handler apdu.UnconfirmedCOVNotificationHandler) error {
	f.unconfirmed = handler
	return nil
}
func (f *covAPDU) AcknowledgeAlarm(_ context.Context, _ netprim.Address, req apdu.AcknowledgeAlarmRequest) error {
	f.acknowledgements = append(f.acknowledgements, req)
	return nil
}
func (f *covAPDU) GetEventInformation(_ context.Context, _ netprim.Address, req apdu.GetEventInformationRequest) (apdu.GetEventInformationACK, error) {
	f.eventRequests = append(f.eventRequests, req)
	return apdu.GetEventInformationACK{MoreEvents: true}, nil
}

func TestSubscribeCOVObjectPropertyAndCancel(t *testing.T) {
	fake := &covAPDU{}
	client := fakeClient(fake)
	target := TargetAddr(netip4(t))
	object := Object{Type: types.ObjectTypeAnalogValue, Instance: 7}
	if err := client.SubscribeCOV(t.Context(), target, COVSubscription{ProcessID: 1, Object: object, Lifetime: time.Minute}); err != nil {
		t.Fatal(err)
	}
	property := types.PropertyIdentifierPresentValue
	increment := float32(0.5)
	if err := client.SubscribeCOV(t.Context(), target, COVSubscription{ProcessID: 2, Object: object, Property: &property, Increment: &increment, Confirmed: true, Lifetime: 10 * time.Minute}); err != nil {
		t.Fatal(err)
	}
	if err := client.SubscribeCOV(t.Context(), target, COVSubscription{ProcessID: 1, Object: object}); err != nil {
		t.Fatal(err)
	}
	if err := client.SubscribeCOV(t.Context(), target, COVSubscription{ProcessID: 2, Object: object, Property: &property, Increment: &increment}); err != nil {
		t.Fatal(err)
	}
	if len(fake.objects) != 2 || *fake.objects[0].Lifetime != 60 || fake.objects[1].Lifetime != nil || fake.objects[1].IssueConfirmedNotifications != nil {
		t.Fatalf("object requests = %#v", fake.objects)
	}
	if len(fake.properties) != 2 || !*fake.properties[0].IssueConfirmedNotifications || *fake.properties[0].COVIncrement != apdu.COVIncrement(0.5) ||
		fake.properties[1].Lifetime != nil || fake.properties[1].IssueConfirmedNotifications != nil || fake.properties[1].COVIncrement != nil {
		t.Fatalf("property requests = %#v", fake.properties)
	}
}

func TestAlarmAndEventRequestsUseResolvedTarget(t *testing.T) {
	fake := &covAPDU{}
	client := fakeClient(fake)
	target := TargetAddr(netip4(t))
	object := Object{Type: types.ObjectTypeAnalogValue, Instance: 7}.OID()
	ack := apdu.AcknowledgeAlarmRequest{
		ProcessIdentifier: 1, EventObjectIdentifier: object,
		EventTimestamp:           apdu.Timestamp{Kind: apdu.TimestampSequence, Sequence: 1},
		AcknowledgementSource:    "operator",
		AcknowledgementTimestamp: apdu.Timestamp{Kind: apdu.TimestampSequence, Sequence: 2},
	}
	if err := client.AcknowledgeAlarm(t.Context(), target, ack); err != nil {
		t.Fatal(err)
	}
	page, err := client.GetEventInformation(t.Context(), target, apdu.GetEventInformationRequest{LastReceivedObjectIdentifier: &object})
	if err != nil || !page.MoreEvents || len(fake.acknowledgements) != 1 || len(fake.eventRequests) != 1 {
		t.Fatalf("page=%#v ack=%d get=%d err=%v", page, len(fake.acknowledgements), len(fake.eventRequests), err)
	}
}

func TestHandleCOVNotificationsConvertsAndMarksConfirmed(t *testing.T) {
	fake := &covAPDU{}
	client := fakeClient(fake)
	received := make(chan COVNotification, 1)
	if err := client.HandleCOVNotifications(func(_ context.Context, notification COVNotification) error {
		received <- notification
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	device, _ := types.NewObjectIdentifier(types.ObjectTypeDevice, 42)
	object, _ := types.NewObjectIdentifier(types.ObjectTypeAnalogValue, 7)
	raw, _ := encoding.EncodeApplicationValue(encoding.AppReal(12.5))
	if err := fake.confirmed(t.Context(), apdu.ConfirmedCOVNotificationIndication{
		SubscriberProcessIdentifier: 9, InitiatingDeviceIdentifier: device, MonitoredObjectIdentifier: object,
		TimeRemaining: 30, Values: []apdu.COVPropertyValue{{PropertyIdentifier: types.PropertyIdentifierPresentValue, Value: raw}},
	}); err != nil {
		t.Fatal(err)
	}
	got := <-received
	if !got.Confirmed || got.ProcessID != 9 || got.InitiatingDevice != 42 || got.Object.String() != "analog-value:7" || len(got.Values) != 1 {
		t.Fatalf("notification = %#v", got)
	}
	if value, ok := got.Values[0].Value.Float64(); !ok || value != 12.5 {
		t.Fatalf("value = %#v", got.Values[0].Value)
	}
}

func TestSubscribeCOVRejectsInvalidShapeBeforeIO(t *testing.T) {
	fake := &covAPDU{}
	client := fakeClient(fake)
	index := uint32(1)
	err := client.SubscribeCOV(t.Context(), TargetAddr(netip4(t)), COVSubscription{ProcessID: 1, Object: Object{Type: types.ObjectTypeAnalogValue, Instance: 1}, ArrayIndex: &index, Lifetime: time.Minute})
	if err == nil || len(fake.objects) != 0 || len(fake.properties) != 0 {
		t.Fatalf("err=%v object=%d property=%d", err, len(fake.objects), len(fake.properties))
	}
}
