package grant

import (
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/metric"
)

const meterName = "github.com/goto/guardian/core/grant"

var (
	metricDriftRemediation, _ = otel.Meter(meterName).Int64Counter(
		"grant_drift_remediation",
		metric.WithDescription("Number of grants remediated due to drift, grouped by remediation status, resource URN, account ID, and provider type"),
	)
)
