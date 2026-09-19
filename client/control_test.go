package client

import (
	"context"
	"testing"
	"time"

	"github.com/worldiety/bacnet/apdu"
	"github.com/worldiety/bacnet/common/netprim"
)

type controlAPDU struct {
	apdu.Client
	dcc    []apdu.DeviceCommunicationControlRequest
	reinit []apdu.ReinitializeDeviceRequest
	times  []time.Time
	utc    []bool
}

func (f *controlAPDU) DeviceCommunicationControl(_ context.Context, _ netprim.Address, req apdu.DeviceCommunicationControlRequest) error {
	f.dcc = append(f.dcc, req)
	return nil
}

func (f *controlAPDU) ReinitializeDevice(_ context.Context, _ netprim.Address, req apdu.ReinitializeDeviceRequest) error {
	f.reinit = append(f.reinit, req)
	return nil
}

func (f *controlAPDU) TimeSynchronization(_ context.Context, _ netprim.Address, instant time.Time, utc bool) error {
	f.times = append(f.times, instant)
	f.utc = append(f.utc, utc)
	return nil
}

func TestControlMethodsResolveTargetAndDelegate(t *testing.T) {
	fake := &controlAPDU{}
	c := fakeClient(fake)
	target := TargetAddr(netip4(t))
	duration := uint16(15)
	password := "secret"
	if err := c.DeviceCommunicationControl(t.Context(), target, apdu.DeviceCommunicationControlDisable, &duration, &password); err != nil {
		t.Fatal(err)
	}
	if len(fake.dcc) != 1 || fake.dcc[0].EnableDisable != apdu.DeviceCommunicationControlDisable || *fake.dcc[0].TimeDurationMinutes != 15 {
		t.Fatalf("unexpected DCC request: %#v", fake.dcc)
	}
	if err := c.ReinitializeDevice(t.Context(), target, apdu.ReinitializeDeviceStateWarmStart, &password); err != nil {
		t.Fatal(err)
	}
	if len(fake.reinit) != 1 || fake.reinit[0].State != apdu.ReinitializeDeviceStateWarmStart {
		t.Fatalf("unexpected reinitialize request: %#v", fake.reinit)
	}
	instant := time.Date(2026, 9, 19, 14, 0, 0, 0, time.FixedZone("CST", 8*60*60))
	if err := c.TimeSynchronization(t.Context(), target, instant, true); err != nil {
		t.Fatal(err)
	}
	if len(fake.times) != 1 || fake.times[0].Location() != time.UTC || fake.times[0].Hour() != 6 || !fake.utc[0] {
		t.Fatalf("unexpected time request: %#v %#v", fake.times, fake.utc)
	}
}
