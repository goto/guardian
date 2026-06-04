package alertmanager

import (
	"context"
	"fmt"

	"github.com/PagerDuty/go-pagerduty"
)

const (
	eventActionTrigger = "trigger"
)

type PDClient struct{}

func NewPDClient() *PDClient {
	return &PDClient{}
}

// Send delivers a trigger event to PagerDuty via Events API v2.
func (c *PDClient) Send(ctx context.Context, event Event) error {
	v2event := pagerduty.V2Event{
		RoutingKey: event.Team,
		Action:     eventActionTrigger,
		DedupKey:   event.DedupKey,
		Payload: &pagerduty.V2Payload{
			Summary:  event.Summary,
			Source:   "guardian",
			Severity: event.Severity,
			Details:  event.Data,
		},
	}
	if _, err := pagerduty.ManageEventWithContext(ctx, v2event); err != nil {
		return fmt.Errorf("error sending pagerduty event: %w", err)
	}
	return nil
}
