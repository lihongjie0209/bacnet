package client

import (
	"context"
	"time"

	"github.com/worldiety/bacnet/apdu"
)

// DeviceCommunicationControl changes a target device's communication mode.
func (c *Client) DeviceCommunicationControl(
	ctx context.Context,
	target Target,
	mode apdu.DeviceCommunicationControlEnableDisable,
	durationMinutes *uint16,
	password *string,
) error {
	dst, _, err := c.resolveTarget(ctx, target)
	if err != nil {
		return err
	}
	req, err := apdu.NewDeviceCommunicationControlRequest(durationMinutes, mode, password)
	if err != nil {
		return err
	}
	reqCtx, cancel := context.WithTimeout(ctx, c.requestBudget())
	defer cancel()
	return c.apduClient().DeviceCommunicationControl(reqCtx, dst, req)
}

// ReinitializeDevice requests a target device lifecycle transition.
func (c *Client) ReinitializeDevice(
	ctx context.Context,
	target Target,
	state apdu.ReinitializeDeviceState,
	password *string,
) error {
	dst, _, err := c.resolveTarget(ctx, target)
	if err != nil {
		return err
	}
	req, err := apdu.NewReinitializeDeviceRequest(state, password)
	if err != nil {
		return err
	}
	reqCtx, cancel := context.WithTimeout(ctx, c.requestBudget())
	defer cancel()
	return c.apduClient().ReinitializeDevice(reqCtx, dst, req)
}

// TimeSynchronization sends local or UTC wall-clock fields to a target device.
func (c *Client) TimeSynchronization(ctx context.Context, target Target, instant time.Time, utc bool) error {
	dst, _, err := c.resolveTarget(ctx, target)
	if err != nil {
		return err
	}
	if utc {
		instant = instant.UTC()
	}
	reqCtx, cancel := context.WithTimeout(ctx, c.requestBudget())
	defer cancel()
	return c.apduClient().TimeSynchronization(reqCtx, dst, instant, utc)
}
