package jobs

import (
	"context"

	"github.com/goto/guardian/domain"
	"github.com/goto/salt/audit"
)

func (h *handler) FetchResources(ctx context.Context) error {
	ctx = audit.WithActor(ctx, domain.SystemActorName)
	h.logger.Info("running fetch resources job")
	return h.providerService.FetchResources(ctx)
}
