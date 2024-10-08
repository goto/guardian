package v1beta1

import (
	"context"
	"fmt"
	"strings"

	"github.com/goto/guardian/pkg/log"

	"github.com/goto/guardian/core/appeal"
	"github.com/goto/guardian/core/grant"

	guardianv1beta1 "github.com/goto/guardian/api/proto/gotocompany/guardian/v1beta1"
	"github.com/goto/guardian/domain"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type ProtoAdapter interface {
	FromProviderProto(*guardianv1beta1.Provider) (*domain.Provider, error)
	FromProviderConfigProto(*guardianv1beta1.ProviderConfig) *domain.ProviderConfig
	ToProviderProto(*domain.Provider) (*guardianv1beta1.Provider, error)
	ToProviderConfigProto(*domain.ProviderConfig) (*guardianv1beta1.ProviderConfig, error)
	ToProviderTypeProto(domain.ProviderType) *guardianv1beta1.ProviderType
	ToRole(*domain.Role) (*guardianv1beta1.Role, error)

	FromPolicyProto(*guardianv1beta1.Policy) *domain.Policy
	ToPolicyProto(*domain.Policy) (*guardianv1beta1.Policy, error)

	ToPolicyAppealConfigProto(policy *domain.Policy) (*guardianv1beta1.PolicyAppealConfig, error)

	FromResourceProto(*guardianv1beta1.Resource) *domain.Resource
	ToResourceProto(*domain.Resource) (*guardianv1beta1.Resource, error)

	ToAppealProto(*domain.Appeal) (*guardianv1beta1.Appeal, error)
	FromCreateAppealProto(*guardianv1beta1.CreateAppealRequest, string) ([]*domain.Appeal, error)
	FromPatchAppealProto(*guardianv1beta1.PatchAppealRequest, string) (*domain.Appeal, error)
	ToApprovalProto(*domain.Approval) (*guardianv1beta1.Approval, error)

	ToGrantProto(*domain.Grant) (*guardianv1beta1.Grant, error)
	FromGrantProto(*guardianv1beta1.Grant) *domain.Grant
	FromUpdateGrantRequestProto(*guardianv1beta1.UpdateGrantRequest) *domain.GrantUpdate

	ToActivityProto(*domain.Activity) (*guardianv1beta1.ProviderActivity, error)

	ToCommentProto(*domain.Comment) *guardianv1beta1.AppealComment
	ToAppealActivityProto(e *domain.Event) (*guardianv1beta1.AppealActivity, error)
	// TODO: remove interface
}

//go:generate mockery --name=resourceService --exported --with-expecter
type resourceService interface {
	Find(context.Context, domain.ListResourcesFilter) ([]*domain.Resource, error)
	GetOne(context.Context, string) (*domain.Resource, error)
	BulkUpsert(context.Context, []*domain.Resource) error
	Update(context.Context, *domain.Resource) error
	Get(context.Context, *domain.ResourceIdentifier) (*domain.Resource, error)
	Delete(context.Context, string) error
	BatchDelete(context.Context, []string) error
	GetResourcesTotalCount(context.Context, domain.ListResourcesFilter) (int64, error)
}

//go:generate mockery --name=activityService --exported --with-expecter
type activityService interface {
	GetOne(context.Context, string) (*domain.Activity, error)
	Find(context.Context, domain.ListProviderActivitiesFilter) ([]*domain.Activity, error)
	Import(context.Context, domain.ListActivitiesFilter) ([]*domain.Activity, error)
}

//go:generate mockery --name=providerService --exported --with-expecter
type providerService interface {
	Create(context.Context, *domain.Provider) error
	Find(context.Context) ([]*domain.Provider, error)
	GetByID(context.Context, string) (*domain.Provider, error)
	GetTypes(context.Context) ([]domain.ProviderType, error)
	GetOne(ctx context.Context, pType, urn string) (*domain.Provider, error)
	Update(context.Context, *domain.Provider) error
	FetchResources(context.Context) error
	GetRoles(ctx context.Context, id, resourceType string) ([]*domain.Role, error)
	ValidateAppeal(context.Context, *domain.Appeal, *domain.Provider, *domain.Policy) error
	GrantAccess(context.Context, domain.Grant) error
	RevokeAccess(context.Context, domain.Grant) error
	Delete(context.Context, string) error
}

//go:generate mockery --name=policyService --exported --with-expecter
type policyService interface {
	Create(context.Context, *domain.Policy) error
	Find(context.Context) ([]*domain.Policy, error)
	GetOne(ctx context.Context, id string, version uint) (*domain.Policy, error)
	Update(context.Context, *domain.Policy) error
}

//go:generate mockery --name=appealService --exported --with-expecter
type appealService interface {
	GetAppealsTotalCount(context.Context, *domain.ListAppealsFilter) (int64, error)
	GetByID(context.Context, string) (*domain.Appeal, error)
	Find(context.Context, *domain.ListAppealsFilter) ([]*domain.Appeal, error)
	Create(context.Context, []*domain.Appeal, ...appeal.CreateAppealOption) error
	Patch(context.Context, *domain.Appeal) error
	Cancel(context.Context, string) (*domain.Appeal, error)
	AddApprover(ctx context.Context, appealID, approvalID, email string) (*domain.Appeal, error)
	DeleteApprover(ctx context.Context, appealID, approvalID, email string) (*domain.Appeal, error)
	UpdateApproval(ctx context.Context, approvalAction domain.ApprovalAction) (*domain.Appeal, error)
	ListComments(context.Context, domain.ListCommentsFilter) ([]*domain.Comment, error)
	CreateComment(context.Context, *domain.Comment) error
	ListActivities(context.Context, string) ([]*domain.Event, error)
}

//go:generate mockery --name=approvalService --exported --with-expecter
type approvalService interface {
	ListApprovals(context.Context, *domain.ListApprovalsFilter) ([]*domain.Approval, error)
	GetApprovalsTotalCount(context.Context, *domain.ListApprovalsFilter) (int64, error)
	BulkInsert(context.Context, []*domain.Approval) error
}

//go:generate mockery --name=grantService --exported --with-expecter
type grantService interface {
	ListUserRoles(context.Context, string) ([]string, error)
	GetGrantsTotalCount(context.Context, domain.ListGrantsFilter) (int64, error)
	List(context.Context, domain.ListGrantsFilter) ([]domain.Grant, error)
	GetByID(context.Context, string) (*domain.Grant, error)
	Update(context.Context, *domain.GrantUpdate) (*domain.Grant, error)
	Restore(ctx context.Context, id, actor, reason string) (*domain.Grant, error)
	Revoke(ctx context.Context, id, actor, reason string, opts ...grant.Option) (*domain.Grant, error)
	BulkRevoke(ctx context.Context, filter domain.RevokeGrantsFilter, actor, reason string) ([]*domain.Grant, error)
	ImportFromProvider(ctx context.Context, criteria grant.ImportFromProviderCriteria) ([]*domain.Grant, error)
}

type GRPCServer struct {
	resourceService resourceService
	activityService activityService
	providerService providerService
	policyService   policyService
	appealService   appealService
	approvalService approvalService
	grantService    grantService
	adapter         ProtoAdapter

	authenticatedUserContextKey interface{}
	logger                      log.Logger

	guardianv1beta1.UnimplementedGuardianServiceServer
}

func NewGRPCServer(
	resourceService resourceService,
	activityService activityService,
	providerService providerService,
	policyService policyService,
	appealService appealService,
	approvalService approvalService,
	grantService grantService,
	adapter ProtoAdapter,
	authenticatedUserContextKey interface{},
	logger log.Logger,
) *GRPCServer {
	return &GRPCServer{
		resourceService:             resourceService,
		activityService:             activityService,
		providerService:             providerService,
		policyService:               policyService,
		appealService:               appealService,
		approvalService:             approvalService,
		grantService:                grantService,
		adapter:                     adapter,
		authenticatedUserContextKey: authenticatedUserContextKey,
		logger:                      logger,
	}
}

func (s *GRPCServer) getUser(ctx context.Context) (string, error) {
	authenticatedEmail, ok := ctx.Value(s.authenticatedUserContextKey).(string)
	if !ok {
		return "", status.Error(codes.Unauthenticated, "unable to get authenticated user from context")
	}

	if strings.TrimSpace(authenticatedEmail) == "" {
		return "", status.Error(codes.Unauthenticated, "unable to get authenticated user from context")
	}

	return authenticatedEmail, nil
}

func (s *GRPCServer) invalidArgument(ctx context.Context, format string, a ...interface{}) error {
	s.logger.Error(ctx, fmt.Sprintf(format, a...))
	return status.Errorf(codes.InvalidArgument, format, a...)
}

func (s *GRPCServer) failedPrecondition(ctx context.Context, format string, a ...interface{}) error {
	s.logger.Error(ctx, fmt.Sprintf(format, a...))
	return status.Errorf(codes.FailedPrecondition, format, a...)
}

func (s *GRPCServer) internalError(ctx context.Context, format string, a ...interface{}) error {
	s.logger.Error(ctx, fmt.Sprintf(format, a...))
	return status.Errorf(codes.Internal, format, a...)
}
