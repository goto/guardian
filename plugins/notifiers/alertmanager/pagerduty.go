package alertmanager

import (
	"context"
	"fmt"

	"github.com/PagerDuty/go-pagerduty"
)

const (
	eventActionTrigger = "trigger"
)

// PDEvent is the generic structure for a PagerDuty Events API v2 trigger event.
type Event struct {
	RoutingKey    string
	DedupKey      string
	EventAction   string
	Summary       string
	Source        string
	Severity      string
	CustomDetails map[string]interface{}
}

// PDSender is the interface for delivering events to PagerDuty.
type PDSender interface {
	Send(ctx context.Context, event Event) error
}

type PDClient struct{}

func NewPDClient() *PDClient {
	return &PDClient{}
}

// Send delivers a trigger event to PagerDuty via Events API v2.
func (c *PDClient) Send(ctx context.Context, event Event) error {
	v2event := pagerduty.V2Event{
		RoutingKey: event.RoutingKey,
		Action:     event.EventAction,
		DedupKey:   event.DedupKey,
		Payload: &pagerduty.V2Payload{
			Summary:  event.Summary,
			Source:   event.Source,
			Severity: event.Severity,
			Details:  event.CustomDetails,
		},
	}
	if _, err := pagerduty.ManageEventWithContext(ctx, v2event); err != nil {
		return fmt.Errorf("sending pagerduty event: %w", err)
	}
	return nil
}
