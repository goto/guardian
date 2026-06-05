package jobs

import (
	guardianotel "github.com/goto/guardian/pkg/opentelemetry"
	"go.opentelemetry.io/otel/metric"
)

const meterName = "github.com/goto/guardian/jobs"

var (
	histGrantDriftCheckDuration = guardianotel.NewLazyFloat64Histogram(
		meterName,
		"grant_drift_check_duration",
		metric.WithDescription("Duration of the grant drift check job in milliseconds"),
		metric.WithUnit("ms"),
	)
)
