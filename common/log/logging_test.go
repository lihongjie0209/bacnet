package log

import (
	"io"
	"log/slog"
	"sync"
	"testing"
)

func TestLoggerCanBeReconfiguredDuringConcurrentUse(t *testing.T) {
	const iterations = 100
	var wait sync.WaitGroup
	wait.Add(2)
	go func() {
		defer wait.Done()
		for range iterations {
			SetLogger(slog.New(slog.NewTextHandler(io.Discard, nil)))
		}
	}()
	go func() {
		defer wait.Done()
		for range iterations {
			Logger.Debug("decode", "bytes", 1)
			Logger.Warn("retry")
			Logger.Error("failure")
		}
	}()
	wait.Wait()
}
