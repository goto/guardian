package jobs

import (
	"context"

	"github.com/go-playground/validator/v10"
	"github.com/goto/guardian/core/grant"
	"github.com/goto/guardian/core/report"
	"github.com/goto/guardian/domain"
	"github.com/goto/guardian/pkg/log"
	"github.com/goto/guardian/plugins/notifiers"
)

//go:generate mockery --name=grantService --exported --with-expecter
type grantService interface {
	List(context.Context, domain.ListGrantsFilter) ([]domain.Grant, error)
	Revoke(ctx context.Context, id, actor, reason string, opts ...grant.Option) (*domain.Grant, error)
	BulkRevoke(ctx context.Context, filter domain.RevokeGrantsFilter, actor, reason string) ([]*domain.Grant, error)
	Update(context.Context, *domain.GrantUpdate) (*domain.Grant, error)
	DormancyCheck(context.Context, domain.DormancyCheckCriteria) error
}

//go:generate mockery --name=providerService --exported
type providerService interface {
	FetchResources(context.Context) error
	Find(context.Context) ([]*domain.Provider, error)
}

//go:generate mockery --name=reportService --exported --with-expecter
type reportService interface {
	GetPendingApprovalsList(ctx context.Context, cfg *report.GetPendingApprovalsListConfig) ([]*report.PendingApproval, error)
}

type crypto interface {
	domain.Crypto
}

type handler struct {
	logger          log.Logger
	grantService    grantService
	reportService   reportService
	providerService providerService
	notifier        notifiers.Client
	crypto          crypto
	validator       *validator.Validate
}

func NewHandler(
	logger log.Logger,
	grantService grantService,
	reportService reportService,
	providerService providerService,
	notifier notifiers.Client,
	crypto crypto,
	validator *validator.Validate,
) *handler {
	return &handler{
		logger:          logger,
		grantService:    grantService,
		reportService:   reportService,
		providerService: providerService,
		notifier:        notifier,
		crypto:          crypto,
		validator:       validator,
	}
}
