package grant

import (
	guardianotel "github.com/goto/guardian/pkg/opentelemetry"
	"go.opentelemetry.io/otel/metric"
)

const meterName = "github.com/goto/guardian/core/grant"

var (
	metricDriftRemediation = guardianotel.NewLazyInt64Counter(
		meterName,
		"grant_drift_remediation",
		metric.WithDescription("Number of grants remediated due to drift, grouped by remediation status, resource URN, account ID, and provider type"),
	)
)
