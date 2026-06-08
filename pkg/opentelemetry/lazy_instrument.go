package opentelemetry

import (
	"sync"

	"go.opentelemetry.io/otel"
	metricapi "go.opentelemetry.io/otel/metric"
)

type LazyInstrument[T any] struct {
	meterName string
	build     func(metricapi.Meter) (T, error)

	once  sync.Once
	value T
}

func NewLazyInstrument[T any](meterName string, build func(metricapi.Meter) (T, error)) *LazyInstrument[T] {
	return &LazyInstrument[T]{
		meterName: meterName,
		build:     build,
	}
}

func (i *LazyInstrument[T]) Get() T {
	i.once.Do(func() {
		i.value, _ = i.build(otel.Meter(i.meterName))
	})

	return i.value
}

func NewLazyInt64Counter(meterName string, name string, options ...metricapi.Int64CounterOption) *LazyInstrument[metricapi.Int64Counter] {
	return NewLazyInstrument(meterName, func(meter metricapi.Meter) (metricapi.Int64Counter, error) {
		return meter.Int64Counter(name, options...)
	})
}

func NewLazyFloat64Histogram(meterName string, name string, options ...metricapi.Float64HistogramOption) *LazyInstrument[metricapi.Float64Histogram] {
	return NewLazyInstrument(meterName, func(meter metricapi.Meter) (metricapi.Float64Histogram, error) {
		return meter.Float64Histogram(name, options...)
	})
}
