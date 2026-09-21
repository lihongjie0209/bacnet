package log

import (
	"context"
	"log/slog"
	"os"
	"sync/atomic"
)

type atomicLogger struct{ value atomic.Pointer[slog.Logger] }

var Logger = newAtomicLogger(slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError})))

func newAtomicLogger(logger *slog.Logger) *atomicLogger {
	value := new(atomicLogger)
	value.value.Store(logger)
	return value
}

func SetLogger(logger *slog.Logger) {
	if logger != nil {
		Logger.value.Store(logger)
	}
}

func (l *atomicLogger) Debug(msg string, args ...any) { l.value.Load().Debug(msg, args...) }
func (l *atomicLogger) Info(msg string, args ...any)  { l.value.Load().Info(msg, args...) }
func (l *atomicLogger) Warn(msg string, args ...any)  { l.value.Load().Warn(msg, args...) }
func (l *atomicLogger) Error(msg string, args ...any) { l.value.Load().Error(msg, args...) }
func (l *atomicLogger) Enabled(ctx context.Context, level slog.Level) bool {
	return l.value.Load().Enabled(ctx, level)
}

func InitLogger(level slog.Level, addSource bool) {
	SetLogger(slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
		AddSource:   addSource,
		Level:       level,
		ReplaceAttr: nil,
	})))
}
