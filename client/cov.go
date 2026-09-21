package client

import (
	"context"
	"fmt"
	"math"
	"time"

	"github.com/worldiety/bacnet/apdu"
	"github.com/worldiety/bacnet/common/netprim"
	"github.com/worldiety/bacnet/common/types"
)

// COVSubscription describes one object-level or property-level subscription.
// A nil Property selects SubscribeCOV; otherwise SubscribeCOVProperty is used.
type COVSubscription struct {
	ProcessID  uint32
	Object     Object
	Property   *types.PropertyIdentifier
	ArrayIndex *uint32
	Increment  *float32
	Confirmed  bool
	Lifetime   time.Duration
}

// COVPropertyValue is one decoded property entry in a notification.
type COVPropertyValue struct {
	Property   types.PropertyIdentifier
	ArrayIndex *uint32
	Value      PropertyValue
	Priority   *uint8
}

// COVNotification is a correlated incoming BACnet COV notification.
type COVNotification struct {
	Source           netprim.Address
	ProcessID        uint32
	InitiatingDevice uint32
	Object           Object
	TimeRemaining    time.Duration
	Confirmed        bool
	Values           []COVPropertyValue
}

// COVNotificationHandler handles both confirmed and unconfirmed notifications.
// A confirmed notification receives its SimpleACK only after this returns nil.
type COVNotificationHandler func(context.Context, COVNotification) error

// SubscribeCOV establishes, renews, or cancels a COV subscription. A zero
// lifetime cancels the matching process/object subscription.
func (c *Client) SubscribeCOV(ctx context.Context, target Target, subscription COVSubscription) error {
	if subscription.ProcessID == 0 {
		return fmt.Errorf("COV process id must be non-zero")
	}
	if subscription.Lifetime < 0 || subscription.Lifetime%time.Second != 0 || subscription.Lifetime/time.Second > math.MaxUint32 {
		return fmt.Errorf("COV lifetime must be a non-negative whole number of seconds within uint32")
	}
	if subscription.Property == nil && (subscription.ArrayIndex != nil || subscription.Increment != nil) {
		return fmt.Errorf("COV array index and increment require a property")
	}
	dst, _, err := c.resolveTarget(ctx, target)
	if err != nil {
		return err
	}
	requestCtx, cancel := context.WithTimeout(ctx, c.requestBudget())
	defer cancel()
	confirmed := subscription.Confirmed
	lifetime := apdu.COVLifetime(subscription.Lifetime / time.Second)
	var confirmedOption *bool
	var lifetimeOption *apdu.COVLifetime
	if subscription.Lifetime > 0 {
		confirmedOption = &confirmed
		lifetimeOption = &lifetime
	}
	if subscription.Property == nil {
		req, err := apdu.NewSubscribeCOVRequest(apdu.SubscriberProcessIdentifier(subscription.ProcessID), subscription.Object.OID(), confirmedOption, lifetimeOption)
		if err != nil {
			return err
		}
		return c.apduClient().SubscribeCOV(requestCtx, dst, req)
	}
	var increment *apdu.COVIncrement
	if subscription.Lifetime > 0 && subscription.Increment != nil {
		value := apdu.COVIncrement(*subscription.Increment)
		increment = &value
	}
	req, err := apdu.NewSubscribeCOVPropertyRequest(
		apdu.SubscriberProcessIdentifier(subscription.ProcessID), subscription.Object.OID(), confirmedOption, lifetimeOption,
		apdu.MonitoredPropertyReference{PropertyIdentifier: *subscription.Property, ArrayIndex: subscription.ArrayIndex}, increment,
	)
	if err != nil {
		return err
	}
	return c.apduClient().SubscribeCOVProperty(requestCtx, dst, req)
}

// HandleCOVNotifications installs the handlers before subscriptions are sent.
// It may be called once for a Client lifetime.
func (c *Client) HandleCOVNotifications(handler COVNotificationHandler) error {
	if handler == nil {
		return fmt.Errorf("COV notification handler is required")
	}
	convert := func(indication apdu.UnconfirmedCOVNotificationIndication, confirmed bool) COVNotification {
		values := make([]COVPropertyValue, len(indication.Values))
		for i, value := range indication.Values {
			values[i] = COVPropertyValue{Property: value.PropertyIdentifier, ArrayIndex: value.ArrayIndex, Value: decodeValue(value.Value), Priority: value.Priority}
		}
		return COVNotification{
			Source: indication.Source, ProcessID: uint32(indication.SubscriberProcessIdentifier),
			InitiatingDevice: indication.InitiatingDeviceIdentifier.Instance(), Object: objectFromOID(indication.MonitoredObjectIdentifier),
			TimeRemaining: time.Duration(indication.TimeRemaining) * time.Second, Confirmed: confirmed, Values: values,
		}
	}
	if err := c.apduClient().HandleConfirmedCOVNotification(func(ctx context.Context, indication apdu.ConfirmedCOVNotificationIndication) error {
		return handler(ctx, convert(indication, true))
	}); err != nil {
		return err
	}
	return c.apduClient().HandleUnconfirmedCOVNotification(func(ctx context.Context, indication apdu.UnconfirmedCOVNotificationIndication) error {
		return handler(ctx, convert(indication, false))
	})
}
