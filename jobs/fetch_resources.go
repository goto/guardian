package jobs

import (
	"context"
	"errors"

	"github.com/goto/guardian/core/provider"
	"github.com/goto/guardian/domain"
	"github.com/goto/salt/audit"
)

func (h *handler) FetchResources(ctx context.Context, cfg Config) error {
	ctx = audit.WithActor(ctx, domain.SystemActorName)
	h.logger.Info(ctx, "running fetch resources job")
	err := h.providerService.FetchResources(ctx)
	if errors.Is(err, provider.ErrPartialResourceSync) {
		h.logger.Warn(ctx, "resource fetch completed with skipped providers", "error", err)
		return nil
	}
	return err
}
