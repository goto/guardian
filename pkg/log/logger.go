package log

import (
	"context"
	"errors"
	"io"

	saltLog "github.com/goto/salt/log"
)

type Logger interface {

	// Debug level message with alternating key/value pairs
	// key should be string, value could be anything printable
	Debug(ctx context.Context, msg string, args ...interface{})

	// Info level message with alternating key/value pairs
	// key should be string, value could be anything printable
	Info(ctx context.Context, msg string, args ...interface{})

	// Warn level message with alternating key/value pairs
	// key should be string, value could be anything printable
	Warn(ctx context.Context, msg string, args ...interface{})

	// Error level message with alternating key/value pairs
	// key should be string, value could be anything printable
	Error(ctx context.Context, msg string, args ...interface{})

	// Fatal level message with alternating key/value pairs
	// key should be string, value could be anything printable
	Fatal(ctx context.Context, msg string, args ...interface{})

	// Level returns priority level for which this logger will filter logs
	Level() string

	// Writer used to print logs
	Writer() io.Writer
}

type LoggerOption func(*CtxLogger)
type metadataContextKey struct{}

type CtxLogger struct {
	log          saltLog.Logger
	keys         []string
	withMetadata func(context.Context) (context.Context, error)
}

// NewCtxLoggerWithSaltLogger returns a logger that will add context value to the log message, wrapped with saltLog.Logger
func NewCtxLoggerWithSaltLogger(log saltLog.Logger, ctxKeys []string, opts ...LoggerOption) *CtxLogger {
	ctxLogger := &CtxLogger{log: log, keys: ctxKeys}
	for _, o := range opts {
		o(ctxLogger)
	}

	return ctxLogger
}

// NewCtxLogger returns a logger that will add context value to the log message
func NewCtxLogger(logLevel string, ctxKeys []string, opts ...LoggerOption) *CtxLogger {
	saltLogger := saltLog.NewLogrus(saltLog.LogrusWithLevel(logLevel))
	ctxLogger := NewCtxLoggerWithSaltLogger(saltLogger, ctxKeys, opts...)
	return ctxLogger
}

func (l *CtxLogger) Debug(ctx context.Context, msg string, args ...interface{}) {
	l.log.Debug(msg, l.addCtxToArgs(ctx, args)...)
}

func (l *CtxLogger) Info(ctx context.Context, msg string, args ...interface{}) {
	l.log.Info(msg, l.addCtxToArgs(ctx, args)...)
}

func (l *CtxLogger) Warn(ctx context.Context, msg string, args ...interface{}) {
	l.log.Warn(msg, l.addCtxToArgs(ctx, args)...)
}

func (l *CtxLogger) Error(ctx context.Context, msg string, args ...interface{}) {
	l.log.Error(msg, l.addCtxToArgs(ctx, args)...)
}

func (l *CtxLogger) Fatal(ctx context.Context, msg string, args ...interface{}) {
	l.log.Fatal(msg, l.addCtxToArgs(ctx, args)...)
}

func (l *CtxLogger) Level() string {
	return l.log.Level()
}

func (l *CtxLogger) Writer() io.Writer {
	return l.log.Writer()
}

// addCtxToArgs adds context value to the existing args slice as key/value pair
func (l *CtxLogger) addCtxToArgs(ctx context.Context, args []interface{}) []interface{} {
	if ctx == nil {
		return args
	}

	for _, key := range l.keys {
		if val, ok := ctx.Value(key).(string); ok {
			args = append(args, key, val)
		}
	}

	return args
}

func WithMetadata(ctx context.Context, md map[string]interface{}) (context.Context, error) {
	existingMetadata := ctx.Value(metadataContextKey{})
	if existingMetadata == nil {
		return context.WithValue(ctx, metadataContextKey{}, md), nil
	}

	// append new metadata
	mapMd, ok := existingMetadata.(map[string]interface{})
	if !ok {
		return nil, errors.New("failed to cast existing metadata to map[string]interface{} type")
	}
	for k, v := range md {
		mapMd[k] = v
	}

	return context.WithValue(ctx, metadataContextKey{}, mapMd), nil
}

func WithMetadataExtractor(fn func(context.Context) map[string]interface{}) LoggerOption {
	return func(s *CtxLogger) {
		s.withMetadata = func(ctx context.Context) (context.Context, error) {
			md := fn(ctx)
			return WithMetadata(ctx, md)
		}
	}
}
