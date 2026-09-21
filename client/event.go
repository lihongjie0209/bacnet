package client

import (
	"context"

	"github.com/worldiety/bacnet/apdu"
)

// HandleConfirmedEventNotification installs the shared confirmed event handler.
// The APDU layer sends SimpleACK only after handler acceptance.
func (c *Client) HandleConfirmedEventNotification(handler apdu.ConfirmedEventNotificationHandler) error {
	return c.apduClient().HandleConfirmedEventNotification(handler)
}

// HandleUnconfirmedEventNotification installs the shared unconfirmed event handler.
func (c *Client) HandleUnconfirmedEventNotification(handler apdu.UnconfirmedEventNotificationHandler) error {
	return c.apduClient().HandleUnconfirmedEventNotification(handler)
}

// AcknowledgeAlarm sends one validated acknowledgement to a resolved target.
func (c *Client) AcknowledgeAlarm(ctx context.Context, target Target, request apdu.AcknowledgeAlarmRequest) error {
	dst, _, err := c.resolveTarget(ctx, target)
	if err != nil {
		return err
	}
	requestCtx, cancel := context.WithTimeout(ctx, c.requestBudget())
	defer cancel()
	return c.apduClient().AcknowledgeAlarm(requestCtx, dst, request)
}

// GetEventInformation requests one active-event page from a resolved target.
func (c *Client) GetEventInformation(ctx context.Context, target Target, request apdu.GetEventInformationRequest) (apdu.GetEventInformationACK, error) {
	dst, _, err := c.resolveTarget(ctx, target)
	if err != nil {
		return apdu.GetEventInformationACK{}, err
	}
	requestCtx, cancel := context.WithTimeout(ctx, c.requestBudget())
	defer cancel()
	return c.apduClient().GetEventInformation(requestCtx, dst, request)
}
