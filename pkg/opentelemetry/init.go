package opentelemetry

import (
	"context"
	"fmt"
	"time"

	"go.opentelemetry.io/contrib/instrumentation/host"
	"go.opentelemetry.io/contrib/instrumentation/runtime"
	"go.opentelemetry.io/otel"

	"go.opentelemetry.io/otel/exporters/otlp/otlpmetric/otlpmetricgrpc"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc"
	"go.opentelemetry.io/otel/exporters/stdout/stdouttrace"
	"go.opentelemetry.io/otel/propagation"
	sdkMetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.20.0"
	"google.golang.org/grpc/encoding/gzip"
)

const gracePeriod = 5 * time.Second

func Init(ctx context.Context, cfg Config) (func() error, error) {
	res, err := resource.New(ctx,
		resource.WithFromEnv(),
		resource.WithTelemetrySDK(),
		resource.WithAttributes(
			semconv.ServiceName(cfg.ServiceName),
			semconv.ServiceVersion(cfg.ServiceVersion),
		),
	)
	if err != nil {
		return nil, fmt.Errorf("error creating resource: %w", err)
	}

	var shutdowns []func() error
	shutdownAll := func() error {
		for _, fn := range shutdowns {
			if err := fn(); err != nil {
				return err
			}
		}
		return nil
	}

	shutdownMetric, err := initGlobalMetrics(ctx, res, cfg)
	if err != nil {
		shutdownAll() //nolint:errcheck
		return nil, fmt.Errorf("error initiating metrics: %w", err)
	}
	shutdowns = append(shutdowns, shutdownMetric)

	shutdownTracer, err := initGlobalTracer(ctx, res, cfg)
	if err != nil {
		shutdownAll() //nolint:errcheck
		return nil, fmt.Errorf("error initiating tracer: %w", err)
	}
	shutdowns = append(shutdowns, shutdownTracer)

	if err := host.Start(); err != nil {
		shutdownAll() //nolint:errcheck
		return nil, fmt.Errorf("error starting host metrics: %w", err)
	}

	if err := runtime.Start(); err != nil {
		shutdownAll() //nolint:errcheck
		return nil, fmt.Errorf("error starting runtime metrics: %w", err)
	}

	return shutdownAll, nil
}

func initGlobalMetrics(ctx context.Context, res *resource.Resource, cfg Config) (func() error, error) {
	exporter, err := otlpmetricgrpc.New(ctx,
		otlpmetricgrpc.WithEndpoint(cfg.OTLP.Endpoint),
		otlpmetricgrpc.WithCompressor(gzip.Name),
		otlpmetricgrpc.WithInsecure(),
	)
	if err != nil {
		return nil, fmt.Errorf("create metric exporter: %w", err)
	}

	reader := sdkMetric.NewPeriodicReader(exporter, sdkMetric.WithInterval(cfg.MetricInterval))
	provider := sdkMetric.NewMeterProvider(sdkMetric.WithReader(reader), sdkMetric.WithResource(res))
	otel.SetMeterProvider(provider)

	return func() error {
		shutdownCtx, cancel := context.WithTimeout(ctx, gracePeriod)
		defer cancel()
		if err := provider.Shutdown(shutdownCtx); err != nil {
			return fmt.Errorf("error shutting down metric provider: %w", err)
		}
		return nil
	}, nil
}

func initGlobalTracer(ctx context.Context, res *resource.Resource, cfg Config) (func() error, error) {
	exporter, err := otlptrace.New(ctx, otlptracegrpc.NewClient(
		otlptracegrpc.WithInsecure(),
		otlptracegrpc.WithEndpoint(cfg.OTLP.Endpoint),
		otlptracegrpc.WithCompressor(gzip.Name),
	))
	if err != nil {
		return nil, fmt.Errorf("create trace exporter: %w", err)
	}

	stdoutExporter, err := stdouttrace.New(stdouttrace.WithPrettyPrint())
	if err != nil {
		return nil, fmt.Errorf("create stdout trace exporter: %w", err)
	}

	tracerProvider := sdktrace.NewTracerProvider(
		sdktrace.WithSampler(sdktrace.AlwaysSample()),
		sdktrace.WithResource(res),
		sdktrace.WithBatcher(exporter),
		sdktrace.WithBatcher(stdoutExporter), // Stdout exporter
	)

	otel.SetTracerProvider(tracerProvider)
	otel.SetTextMapPropagator(propagation.NewCompositeTextMapPropagator(
		propagation.TraceContext{}, propagation.Baggage{},
	))

	return func() error {
		shutdownCtx, cancel := context.WithTimeout(ctx, gracePeriod)
		defer cancel()
		if err := tracerProvider.Shutdown(shutdownCtx); err != nil {
			return fmt.Errorf("error shutting down trace provider: %w", err)
		}
		return nil
	}, nil
}
