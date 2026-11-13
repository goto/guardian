package notifiers

import (
	"context"
	"testing"

	"github.com/goto/guardian/domain"
)

type recipientCaptureClient struct{ received []domain.Notification }

func (c *recipientCaptureClient) Notify(ctx context.Context, items []domain.Notification) []error {
	c.received = append(c.received, items...)
	return nil
}

func TestRecipientCriteriaApplyIndividuallyInEitherOrder(t *testing.T) {
	for _, first := range []string{"c@example.com", "d@example.com"} {
		t.Run(first, func(t *testing.T) {
			second := "d@example.com"
			if first == second {
				second = "c@example.com"
			}
			client := &recipientCaptureClient{}
			manager := &NotifyManager{clients: []Client{client}, configs: []Config{{Criteria: `$email == "d@example.com"`}}}
			if errs := manager.Notify(context.Background(), []domain.Notification{{User: first}, {User: second}}); len(errs) > 0 {
				t.Fatal(errs)
			}
			if len(client.received) != 1 || client.received[0].User != "d@example.com" {
				t.Fatalf("wrong selected recipients: %+v", client.received)
			}
		})
	}
}

func TestLegacyNotifierNeedsNoCardMigration(t *testing.T) {
	manager := &NotifyManager{clients: []Client{&recipientCaptureClient{}}}
	if err := manager.ConfigureCards(context.Background(), nil, nil); err != nil {
		t.Fatal(err)
	}
}
