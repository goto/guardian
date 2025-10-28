package v1beta1

import (
	"context"
	"errors"
	"sync"

	"github.com/mitchellh/mapstructure"
	"golang.org/x/sync/errgroup"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	guardianv1beta1 "github.com/goto/guardian/api/proto/gotocompany/guardian/v1beta1"
	"github.com/goto/guardian/core/appeal"
	"github.com/goto/guardian/domain"
	slicesUtil "github.com/goto/guardian/pkg/slices"
)

func (s *GRPCServer) ListUserApprovals(ctx context.Context, req *guardianv1beta1.ListUserApprovalsRequest) (*guardianv1beta1.ListUserApprovalsResponse, error) {
	user, err := s.getUser(ctx)
	if err != nil {
		return nil, status.Error(codes.Unauthenticated, err.Error())
	}

	filter := &domain.ListApprovalsFilter{
		Q:               req.GetQ(),
		AccountID:       req.GetAccountId(),
		AccountTypes:    req.GetAccountTypes(),
		ResourceTypes:   req.GetResourceTypes(),
		CreatedBy:       user,
		Statuses:        req.GetStatuses(),
		OrderBy:         req.GetOrderBy(),
		Size:            int(req.GetSize()),
		Offset:          int(req.GetOffset()),
		AppealStatuses:  req.GetAppealStatuses(),
		Stale:           req.GetStale(),
		RoleStartsWith:  req.GetRoleStartsWith(),
		RoleEndsWith:    req.GetRoleEndsWith(),
		RoleContains:    req.GetRoleContains(),
		StepNames:       req.GetStepNames(),
		ProviderTypes:   req.GetProviderTypes(),
		ProviderURNs:    req.GetProviderUrns(),
		Actors:          req.GetActors(),
		SummaryGroupBys: slicesUtil.GenericsStandardizeSliceNilAble(req.GetSummaryGroupBys()),
		SummaryUniques:  slicesUtil.GenericsStandardizeSliceNilAble(req.GetSummaryUniques()),
		FieldMasks:      slicesUtil.GenericsStandardizeSliceNilAble(req.GetFieldMasks()),
		StartTime:       s.adapter.FromTimeProto(req.GetStartTime()),
		EndTime:         s.adapter.FromTimeProto(req.GetEndTime()),
		ResourceUrns:    slicesUtil.GenericsStandardizeSliceNilAble(req.GetResourceUrns()),
		Roles:           slicesUtil.GenericsStandardizeSliceNilAble(req.GetRoles()),
		Requestors:      slicesUtil.GenericsStandardizeSliceNilAble(req.GetRequestors()),
		AccountIDs:      slicesUtil.GenericsStandardizeSliceNilAble(req.GetAccountIds()),
	}

	approvals, total, summary, err := s.listApprovals(ctx, filter)
	if err != nil {
		return nil, err
	}

	return &guardianv1beta1.ListUserApprovalsResponse{
		Approvals: approvals,
		Total:     int32(total),
		Summary:   summary,
	}, nil
}

func (s *GRPCServer) ListApprovals(ctx context.Context, req *guardianv1beta1.ListApprovalsRequest) (*guardianv1beta1.ListApprovalsResponse, error) {
	filter := &domain.ListApprovalsFilter{
		Q:               req.GetQ(),
		AccountID:       req.GetAccountId(),
		AccountTypes:    req.GetAccountTypes(),
		ResourceTypes:   req.GetResourceTypes(),
		CreatedBy:       req.GetCreatedBy(),
		Statuses:        req.GetStatuses(),
		OrderBy:         req.GetOrderBy(),
		Size:            int(req.GetSize()),
		Offset:          int(req.GetOffset()),
		AppealStatuses:  req.GetAppealStatuses(),
		Stale:           req.GetStale(),
		RoleStartsWith:  req.GetRoleStartsWith(),
		RoleEndsWith:    req.GetRoleEndsWith(),
		RoleContains:    req.GetRoleContains(),
		StepNames:       req.GetStepNames(),
		ProviderTypes:   req.GetProviderTypes(),
		ProviderURNs:    req.GetProviderUrns(),
		Actors:          req.GetActors(),
		SummaryGroupBys: slicesUtil.GenericsStandardizeSliceNilAble(req.GetSummaryGroupBys()),
		SummaryUniques:  slicesUtil.GenericsStandardizeSliceNilAble(req.GetSummaryUniques()),
		FieldMasks:      slicesUtil.GenericsStandardizeSliceNilAble(req.GetFieldMasks()),
		StartTime:       s.adapter.FromTimeProto(req.GetStartTime()),
		EndTime:         s.adapter.FromTimeProto(req.GetEndTime()),
		ResourceUrns:    slicesUtil.GenericsStandardizeSliceNilAble(req.GetResourceUrns()),
		Roles:           slicesUtil.GenericsStandardizeSliceNilAble(req.GetRoles()),
		Requestors:      slicesUtil.GenericsStandardizeSliceNilAble(req.GetRequestors()),
		AccountIDs:      slicesUtil.GenericsStandardizeSliceNilAble(req.GetAccountIds()),
	}

	approvals, total, summary, err := s.listApprovals(ctx, filter)
	if err != nil {
		return nil, err
	}

	return &guardianv1beta1.ListApprovalsResponse{
		Approvals: approvals,
		Total:     int32(total),
		Summary:   summary,
	}, nil
}

func (s *GRPCServer) UpdateApproval(ctx context.Context, req *guardianv1beta1.UpdateApprovalRequest) (*guardianv1beta1.UpdateApprovalResponse, error) {
	actor, err := s.getUser(ctx)
	if err != nil {
		return nil, status.Error(codes.Unauthenticated, err.Error())
	}

	id := req.GetId()
	a, err := s.appealService.UpdateApproval(ctx, domain.ApprovalAction{
		AppealID:     id,
		ApprovalName: req.GetApprovalName(),
		Actor:        actor,
		Action:       req.GetAction().GetAction(),
		Reason:       req.GetAction().GetReason(),
	})
	if err != nil {
		switch {
		case
			errors.Is(err, appeal.ErrInvalidUpdateApprovalParameter),
			errors.Is(err, appeal.ErrAppealIDEmptyParam),
			errors.Is(err, appeal.ErrActionInvalidValue):
			return nil, s.invalidArgument(ctx, err.Error())
		case
			errors.Is(err, appeal.ErrAppealNotEligibleForApproval),
			errors.Is(err, appeal.ErrAppealStatusUnrecognized),
			errors.Is(err, appeal.ErrApprovalNotEligibleForAction),
			errors.Is(err, appeal.ErrApprovalStatusUnrecognized):
			return nil, s.failedPrecondition(ctx, err.Error())
		case errors.Is(err, appeal.ErrActionForbidden):
			return nil, status.Error(codes.PermissionDenied, "permission denied")
		case
			errors.Is(err, appeal.ErrAppealNotFound),
			errors.Is(err, appeal.ErrApprovalNotFound):
			return nil, status.Errorf(codes.NotFound, err.Error())
		default:
			return nil, s.internalError(ctx, "failed to update approval: %v", err)
		}
	}

	appealProto, err := s.adapter.ToAppealProto(a)
	if err != nil {
		return nil, s.internalError(ctx, "failed to parse appeal: %v", err)
	}

	return &guardianv1beta1.UpdateApprovalResponse{
		Appeal: appealProto,
	}, nil
}

func (s *GRPCServer) GenerateUserApprovalSummaries(ctx context.Context, req *guardianv1beta1.GenerateUserApprovalSummariesRequest) (*guardianv1beta1.GenerateUserApprovalSummariesResponse, error) {
	user, err := s.getUser(ctx)
	if err != nil {
		return nil, status.Error(codes.Unauthenticated, err.Error())
	}

	items, err := s.listApprovalsSummaries(ctx, user, req.GetSummaryItems())
	if err != nil {
		return nil, err
	}

	return &guardianv1beta1.GenerateUserApprovalSummariesResponse{
		SummaryItems: items,
	}, nil
}

func (s *GRPCServer) GenerateApprovalSummaries(ctx context.Context, req *guardianv1beta1.GenerateApprovalSummariesRequest) (*guardianv1beta1.GenerateApprovalSummariesResponse, error) {
	items, err := s.listApprovalsSummaries(ctx, "", req.GetSummaryItems())
	if err != nil {
		return nil, err
	}

	return &guardianv1beta1.GenerateApprovalSummariesResponse{
		SummaryItems: items,
	}, nil
}

func (s *GRPCServer) AddApprover(ctx context.Context, req *guardianv1beta1.AddApproverRequest) (*guardianv1beta1.AddApproverResponse, error) {
	a, err := s.appealService.AddApprover(ctx, req.GetAppealId(), req.GetApprovalId(), req.GetEmail())
	switch {
	case errors.Is(err, appeal.ErrAppealIDEmptyParam),
		errors.Is(err, appeal.ErrApprovalIDEmptyParam),
		errors.Is(err, appeal.ErrApproverEmail),
		errors.Is(err, appeal.ErrUnableToAddApprover):
		return nil, s.invalidArgument(ctx, "unable to process the request: %s", err)
	case errors.Is(err, appeal.ErrAppealNotFound),
		errors.Is(err, appeal.ErrApprovalNotFound):
		return nil, status.Errorf(codes.NotFound, "resource not found: %s", err)
	case err != nil:
		return nil, s.internalError(ctx, "failed to add approver: %s", err)
	}

	appealProto, err := s.adapter.ToAppealProto(a)
	if err != nil {
		return nil, s.internalError(ctx, "failed to parse appeal: %s", err)
	}

	return &guardianv1beta1.AddApproverResponse{
		Appeal: appealProto,
	}, nil
}

func (s *GRPCServer) DeleteApprover(ctx context.Context, req *guardianv1beta1.DeleteApproverRequest) (*guardianv1beta1.DeleteApproverResponse, error) {
	a, err := s.appealService.DeleteApprover(ctx, req.GetAppealId(), req.GetApprovalId(), req.GetEmail())
	switch {
	case errors.Is(err, appeal.ErrAppealIDEmptyParam),
		errors.Is(err, appeal.ErrApprovalIDEmptyParam),
		errors.Is(err, appeal.ErrApproverEmail),
		errors.Is(err, appeal.ErrUnableToDeleteApprover):
		return nil, s.invalidArgument(ctx, "unable to process the request: %s", err)
	case errors.Is(err, appeal.ErrAppealNotFound),
		errors.Is(err, appeal.ErrApprovalNotFound):
		return nil, status.Errorf(codes.NotFound, "resource not found: %s", err)
	case err != nil:
		return nil, s.internalError(ctx, "failed to delete approver: %s", err)
	}

	appealProto, err := s.adapter.ToAppealProto(a)
	if err != nil {
		return nil, s.internalError(ctx, "failed to parse appeal: %s", err)
	}

	return &guardianv1beta1.DeleteApproverResponse{
		Appeal: appealProto,
	}, nil
}

func (s *GRPCServer) listApprovals(ctx context.Context, filter *domain.ListApprovalsFilter) ([]*guardianv1beta1.Approval, int64, *guardianv1beta1.SummaryResult, error) {
	eg, ctx := errgroup.WithContext(ctx)
	var approvals []*domain.Approval
	var summary *domain.SummaryResult
	var total int64

	if filter.WithApprovals() {
		eg.Go(func() error {
			approvalRecords, err := s.approvalService.ListApprovals(ctx, filter)
			if err != nil {
				return s.internalError(ctx, "failed to get approval list: %s", err)
			}
			approvals = approvalRecords
			return nil
		})
	}
	if filter.WithTotal() {
		eg.Go(func() error {
			totalRecord, err := s.approvalService.GetApprovalsTotalCount(ctx, filter)
			if err != nil {
				return s.internalError(ctx, "failed to get approval list: %v", err)
			}
			total = totalRecord
			return nil
		})
	}
	if filter.WithSummary() {
		eg.Go(func() error {
			var e error
			summary, e = s.approvalService.GenerateSummary(ctx, *filter)
			if e != nil {
				switch {
				case errors.Is(e, domain.ErrInvalidUniqueInput) ||
					errors.Is(e, domain.ErrEmptyUniqueTableName) ||
					errors.Is(e, domain.ErrEmptyUniqueColumnName) ||
					errors.Is(e, domain.ErrNotSupportedUniqueTableName) ||
					errors.Is(e, domain.ErrInvalidGroupInput) ||
					errors.Is(e, domain.ErrEmptyGroupTableName) ||
					errors.Is(e, domain.ErrEmptyGroupColumnName) ||
					errors.Is(e, domain.ErrNotSupportedGroupTableName):
					return s.invalidArgument(ctx, "invalid summary argument: %s", e.Error())
				default:
					return s.internalError(ctx, "failed to generate summary: %s", e.Error())
				}
			}
			return nil
		})
	}
	if err := eg.Wait(); err != nil {
		return nil, 0, nil, err
	}

	var approvalsProto []*guardianv1beta1.Approval
	for _, a := range approvals {
		approvalProto, err := s.adapter.ToApprovalProto(a)
		if err != nil {
			return nil, 0, nil, s.internalError(ctx, "failed to parse approval: %v: %s", a.ID, err)
		}
		approvalsProto = append(approvalsProto, approvalProto)
	}

	summaryProto, err := s.adapter.ToSummaryProto(summary)
	if err != nil {
		return nil, 0, nil, s.internalError(ctx, "failed to parse summary: %v", err)
	}

	return approvalsProto, total, summaryProto, nil
}

func (s *GRPCServer) listApprovalsSummaries(ctx context.Context, actor string, items map[string]*guardianv1beta1.SummaryParameters) (map[string]*guardianv1beta1.SummaryResult, error) {
	summaryItems := make(map[string]*guardianv1beta1.SummaryResult, len(items))
	mu := sync.Mutex{}
	eg, egCtx := errgroup.WithContext(ctx)
	eg.SetLimit(3)

	for key, parameters := range items {
		key := key
		parameters := parameters
		eg.Go(func() error {
			var listApprovalsFilter *domain.ListApprovalsFilter
			if err := mapstructure.Decode(toGoMap(parameters.GetFilters()), &listApprovalsFilter); err != nil {
				return s.invalidArgument(egCtx, "failed to decode filters for %q: %s", key, err)
			}
			if actor != "" {
				if listApprovalsFilter == nil {
					listApprovalsFilter = &domain.ListApprovalsFilter{}
				}
				listApprovalsFilter.CreatedBy = actor
			}

			summary, err := s.approvalService.GenerateApprovalSummary(egCtx, listApprovalsFilter, parameters.GetGroupBys())
			if err != nil {
				switch {
				case errors.Is(err, domain.ErrInvalidUniqueInput) ||
					errors.Is(err, domain.ErrEmptyUniqueTableName) ||
					errors.Is(err, domain.ErrEmptyUniqueColumnName) ||
					errors.Is(err, domain.ErrNotSupportedUniqueTableName) ||
					errors.Is(err, domain.ErrInvalidGroupInput) ||
					errors.Is(err, domain.ErrEmptyGroupTableName) ||
					errors.Is(err, domain.ErrEmptyGroupColumnName) ||
					errors.Is(err, domain.ErrNotSupportedGroupTableName):
					return s.invalidArgument(egCtx, "invalid argument for %q: %s", key, err)
				default:
					return s.internalError(egCtx, "failed to generate approval summary for %q: %s", key, err)
				}
			}

			summaryProto, err := s.adapter.ToSummaryProto(summary)
			if err != nil {
				return s.internalError(egCtx, "failed to parse summary result for %q: %s", key, err)
			}
			mu.Lock()
			summaryItems[key] = summaryProto
			mu.Unlock()

			return nil
		})
	}

	if err := eg.Wait(); err != nil {
		return nil, err
	}
	return summaryItems, nil
}
