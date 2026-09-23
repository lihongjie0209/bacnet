package mstp

import (
	"errors"
	"testing"
	"time"
)

func testMasterConfig() MasterConfig {
	return MasterConfig{
		LocalMAC: 3, MaxMaster: 7, MaxInfoFrames: 2, MaxPending: 2,
		ReplyTimeout: 40 * time.Millisecond, UsageTimeout: 10 * time.Millisecond,
		TokenRetryTimeout: 5 * time.Millisecond, PollInterval: 20 * time.Millisecond,
		NoTokenTimeout: 50 * time.Millisecond,
	}
}

func TestMasterSendsQueuedFramesAndPassesToken(t *testing.T) {
	now := time.Unix(1, 0)
	master, err := NewMaster(testMasterConfig(), now)
	if err != nil {
		t.Fatal(err)
	}
	_ = master.Enqueue(5, []byte{1}, false)
	_ = master.Enqueue(6, []byte{2}, false)
	frames, err := master.Handle(Frame{Type: FrameToken, Destination: 3, Source: 2}, now)
	if err != nil || len(frames) != 1 || frames[0].Type != FrameDataNotExpectingReply || frames[0].Destination != 5 {
		t.Fatalf("first=%+v error=%v", frames, err)
	}
	frames = master.Tick(now.Add(10 * time.Millisecond))
	if len(frames) != 1 || frames[0].Destination != 6 {
		t.Fatalf("second=%+v", frames)
	}
	frames = master.Tick(now.Add(20 * time.Millisecond))
	if len(frames) != 1 || frames[0].Type != FramePollForMaster || frames[0].Destination != 4 {
		t.Fatalf("poll=%+v", frames)
	}
	frames, err = master.Handle(Frame{Type: FrameReplyToPollForMaster, Destination: 3, Source: 4}, now.Add(21*time.Millisecond))
	if err != nil || len(frames) != 1 || frames[0].Type != FrameToken || frames[0].Destination != 4 {
		t.Fatalf("pass=%+v error=%v", frames, err)
	}
}

func TestMasterReplyRecoveryAndBounds(t *testing.T) {
	config := testMasterConfig()
	now := time.Unix(2, 0)
	master, err := NewMaster(config, now)
	if err != nil {
		t.Fatal(err)
	}
	_ = master.Enqueue(5, []byte{1}, true)
	frames, _ := master.Handle(Frame{Type: FrameToken, Destination: 3, Source: 2}, now)
	if len(frames) != 1 || frames[0].Type != FrameDataExpectingReply {
		t.Fatalf("request=%+v", frames)
	}
	if frames = master.Tick(now.Add(39 * time.Millisecond)); len(frames) != 0 {
		t.Fatalf("early=%+v", frames)
	}
	if frames = master.Tick(now.Add(40 * time.Millisecond)); len(frames) != 1 || frames[0].Type != FramePollForMaster {
		t.Fatalf("timeout=%+v", frames)
	}
	frames, err = master.Handle(Frame{Type: FrameDataExpectingReply, Destination: 3, Source: 5, Data: []byte{9}}, now.Add(time.Second))
	if err != nil || len(frames) != 1 || frames[0].Type != FrameReplyPostponed {
		t.Fatalf("postponed=%+v error=%v", frames, err)
	}

	other, _ := NewMaster(config, now)
	recoveryAt := now.Add(config.NoTokenTimeout + time.Duration(config.LocalMAC)*config.TokenRetryTimeout)
	if frames = other.Tick(recoveryAt); len(frames) != 1 || frames[0].Type != FramePollForMaster {
		t.Fatalf("recovery=%+v", frames)
	}
	if _, err = other.Handle(Frame{Type: FrameDataNotExpectingReply, Destination: 7, Source: config.LocalMAC, Data: []byte{1}}, recoveryAt); !errors.Is(err, ErrDuplicateMAC) {
		t.Fatalf("duplicate error=%v", err)
	}
	queue, _ := NewMaster(config, now)
	_ = queue.Enqueue(1, []byte{1}, false)
	_ = queue.Enqueue(2, []byte{2}, false)
	if err = queue.Enqueue(3, []byte{3}, false); !errors.Is(err, ErrQueueFull) {
		t.Fatalf("queue error=%v", err)
	}
	if err = queue.Enqueue(255, []byte{1}, true); err == nil {
		t.Fatal("accepted broadcast expecting reply")
	}
}

func TestMasterConfigValidation(t *testing.T) {
	config := testMasterConfig()
	config.MaxMaster = 2
	if _, err := NewMaster(config, time.Time{}); err == nil {
		t.Fatal("accepted max-master below local MAC")
	}
}
