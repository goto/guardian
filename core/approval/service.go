package approval

import (
	"context"
	"strings"

	"github.com/goto/guardian/domain"
	slicesUtil "github.com/goto/guardian/pkg/slices"
	"github.com/goto/guardian/utils"
)

//go:generate mockery --name=repository --exported --with-expecter
type repository interface {
	BulkInsert(context.Context, []*domain.Approval) error
	GetApprovalsTotalCount(context.Context, *domain.ListApprovalsFilter) (int64, error)
	ListApprovals(context.Context, *domain.ListApprovalsFilter) ([]*domain.Approval, error)
	AddApprover(context.Context, *domain.Approver) error
	DeleteApprover(ctx context.Context, approvalID, email string) error
	UpdateApproval(ctx context.Context, approval *domain.Approval) error
	GenerateApprovalSummary(ctx context.Context, filter *domain.ListApprovalsFilter, groupBys []string) (*domain.SummaryResult, error)
	GenerateSummary(context.Context, domain.ListApprovalsFilter) (*domain.SummaryResult, error)
}

//go:generate mockery --name=policyService --exported --with-expecter
type policyService interface {
	GetOne(context.Context, string, uint) (*domain.Policy, error)
}

//go:generate mockery --name=grantService --exported --with-expecter
type grantService interface {
	List(ctx context.Context, filter domain.ListGrantsFilter) ([]domain.Grant, error)
}

type ServiceDeps struct {
	Repository    repository
	PolicyService policyService
}
type Service struct {
	repo          repository
	policyService policyService
	grantService  grantService
}

func NewService(deps ServiceDeps) *Service {
	return &Service{
		repo:          deps.Repository,
		policyService: deps.PolicyService,
	}
}

func (s *Service) SetGrantService(g grantService) {
	s.grantService = g
}

func (s *Service) ListApprovals(ctx context.Context, filters *domain.ListApprovalsFilter) ([]*domain.Approval, error) {
	approvals, err := s.repo.ListApprovals(ctx, filters)
	if err != nil {
		return nil, err
	}

	if filters.WithPreviousGrant && s.grantService != nil && len(approvals) > 0 {
		if err := s.populatePreviousGrantExpirationDate(ctx, approvals); err != nil {
			return nil, err
		}
	}

	return approvals, nil
}

func (s *Service) populatePreviousGrantExpirationDate(ctx context.Context, approvals []*domain.Approval) error {
	accountIDs := make([]string, 0, len(approvals))
	resourceIDs := make([]string, 0, len(approvals))
	roles := make([]string, 0, len(approvals))
	for _, a := range approvals {
		if a.Appeal == nil {
			continue
		}
		accountIDs = append(accountIDs, a.Appeal.AccountID)
		resourceIDs = append(resourceIDs, a.Appeal.ResourceID)
		roles = append(roles, a.Appeal.Role)
	}
	if len(accountIDs) == 0 {
		return nil
	}

	grants, err := s.grantService.List(ctx, domain.ListGrantsFilter{
		AccountIDs:  slicesUtil.GenericsStandardizeSlice(accountIDs),
		ResourceIDs: slicesUtil.GenericsStandardizeSlice(resourceIDs),
		Roles:       slicesUtil.GenericsStandardizeSlice(roles),
		OrderBy:     []string{"created_at:desc"},
	})
	if err != nil {
		return err
	}

	// First grant per (account_id, resource_id, role) wins because the list is sorted by created_at DESC.
	latestByKey := make(map[string]*domain.Grant, len(grants))
	for i, g := range grants {
		key := previousGrantKey(g.AccountID, g.ResourceID, g.Role)
		if _, ok := latestByKey[key]; !ok {
			latestByKey[key] = &grants[i]
		}
	}

	for _, a := range approvals {
		if a.Appeal == nil {
			continue
		}
		key := previousGrantKey(a.Appeal.AccountID, a.Appeal.ResourceID, a.Appeal.Role)
		if g, ok := latestByKey[key]; ok && g.ExpirationDate != nil {
			expirationDate := *g.ExpirationDate
			a.PreviousGrantExpirationDate = &expirationDate
		}
	}

	return nil
}

func previousGrantKey(accountID, resourceID, role string) string {
	return strings.ToLower(accountID) + "|" + resourceID + "|" + role
}

func (s *Service) GetApprovalsTotalCount(ctx context.Context, filters *domain.ListApprovalsFilter) (int64, error) {
	return s.repo.GetApprovalsTotalCount(ctx, filters)
}

func (s *Service) GenerateApprovalSummary(ctx context.Context, filters *domain.ListApprovalsFilter, groupBys []string) (*domain.SummaryResult, error) {
	// remove non-filter fields
	filters.Size = 0
	filters.Offset = 0

	result, err := s.repo.GenerateApprovalSummary(ctx, filters, groupBys)
	if err != nil {
		return nil, err
	}

	filtersMap, err := utils.StructToMap(filters)
	if err != nil {
		return nil, err
	}

	appliedParameters := &domain.SummaryParameters{
		Filters:  filtersMap,
		GroupBys: groupBys,
	}
	result.AppliedParameters = appliedParameters

	return result, nil
}

func (s *Service) GenerateSummary(ctx context.Context, filter domain.ListApprovalsFilter) (*domain.SummaryResult, error) {
	return s.repo.GenerateSummary(ctx, filter)
}

func (s *Service) BulkInsert(ctx context.Context, approvals []*domain.Approval) error {
	return s.repo.BulkInsert(ctx, approvals)
}

func (s *Service) AddApprover(ctx context.Context, approvalID, email string) error {
	return s.repo.AddApprover(ctx, &domain.Approver{
		ApprovalID: approvalID,
		Email:      email,
	})
}

func (s *Service) DeleteApprover(ctx context.Context, approvalID, email string) error {
	return s.repo.DeleteApprover(ctx, approvalID, email)
}

func (s *Service) UpdateApproval(ctx context.Context, approval *domain.Approval) error {
	return s.repo.UpdateApproval(ctx, approval)
}
