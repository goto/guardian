package jobs

import (
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/metric"
)

const meterName = "github.com/goto/guardian/jobs"

var (
	histGrantDriftCheckDuration, _ = otel.Meter(meterName).Float64Histogram(
		"grant_drift_check_duration",
		metric.WithDescription("Duration of the grant drift check job in milliseconds"),
		metric.WithUnit("ms"),
	)
)
