package slacklark

import (
	"context"

	"github.com/goto/guardian/plugins/notifiers/lark"
	"github.com/goto/guardian/plugins/notifiers/slack"

	"github.com/goto/guardian/domain"
)

type Notifier struct {
	SlackNotifier *slack.Notifier
	LarkNotifier  *lark.Notifier
}

func NewNotifier(slackNotifier *slack.Notifier, larkNotifier *lark.Notifier) *Notifier {
	return &Notifier{
		SlackNotifier: slackNotifier,
		LarkNotifier:  larkNotifier,
	}
}

func (n *Notifier) Notify(ctx context.Context, items []domain.Notification) []error {
	errs := make([]error, 0)
	n.LarkNotifier.Notify(ctx, items)
	n.SlackNotifier.Notify(ctx, items)

	return errs
}
