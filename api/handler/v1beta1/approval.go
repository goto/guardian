package v1beta1

import (
	"context"
	"errors"

	"golang.org/x/sync/errgroup"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	guardianv1beta1 "github.com/goto/guardian/api/proto/gotocompany/guardian/v1beta1"
	"github.com/goto/guardian/core/appeal"
	"github.com/goto/guardian/domain"
)

func (s *GRPCServer) ListUserApprovals(ctx context.Context, req *guardianv1beta1.ListUserApprovalsRequest) (*guardianv1beta1.ListUserApprovalsResponse, error) {
	user, err := s.getUser(ctx)
	if err != nil {
		return nil, status.Error(codes.Unauthenticated, err.Error())
	}

	approvals, total, err := s.listApprovals(ctx, &domain.ListApprovalsFilter{
		Q:              req.GetQ(),
		AccountID:      req.GetAccountId(),
		AccountTypes:   req.GetAccountTypes(),
		ResourceTypes:  req.GetResourceTypes(),
		CreatedBy:      user,
		Statuses:       req.GetStatuses(),
		OrderBy:        req.GetOrderBy(),
		Size:           int(req.GetSize()),
		Offset:         int(req.GetOffset()),
		AppealStatuses: req.GetAppealStatuses(),
		Stale:          req.GetStale(),
		RoleStartsWith: req.GetRoleStartsWith(),
		RoleEndsWith:   req.GetRoleEndsWith(),
		RoleContains:   req.GetRoleContains(),
		StepNames:      req.GetStepNames(),
	})
	if err != nil {
		return nil, err
	}

	return &guardianv1beta1.ListUserApprovalsResponse{
		Approvals: approvals,
		Total:     int32(total),
	}, nil
}

func (s *GRPCServer) ListApprovals(ctx context.Context, req *guardianv1beta1.ListApprovalsRequest) (*guardianv1beta1.ListApprovalsResponse, error) {
	approvals, total, err := s.listApprovals(ctx, &domain.ListApprovalsFilter{
		Q:              req.GetQ(),
		AccountID:      req.GetAccountId(),
		AccountTypes:   req.GetAccountTypes(),
		ResourceTypes:  req.GetResourceTypes(),
		CreatedBy:      req.GetCreatedBy(),
		Statuses:       req.GetStatuses(),
		OrderBy:        req.GetOrderBy(),
		Size:           int(req.GetSize()),
		Offset:         int(req.GetOffset()),
		AppealStatuses: req.GetAppealStatuses(),
		Stale:          req.GetStale(),
		RoleStartsWith: req.GetRoleStartsWith(),
		RoleEndsWith:   req.GetRoleEndsWith(),
		RoleContains:   req.GetRoleContains(),
		StepNames:      req.GetStepNames(),
	})
	if err != nil {
		return nil, err
	}

	return &guardianv1beta1.ListApprovalsResponse{
		Approvals: approvals,
		Total:     int32(total),
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

func (s *GRPCServer) GenerateListUserApprovalsSummaries(ctx context.Context, req *guardianv1beta1.GenerateListUserApprovalsSummariesRequest) (*guardianv1beta1.GenerateListUserApprovalsSummariesResponse, error) {
	summaries, total, err := s.listApprovalsSummaries(ctx, true, req.GetRequests())
	if err != nil {
		return nil, err
	}

	return &guardianv1beta1.GenerateListUserApprovalsSummariesResponse{
		Summaries: summaries,
		Total:     total,
	}, nil
}

func (s *GRPCServer) GenerateListApprovalsSummaries(ctx context.Context, req *guardianv1beta1.GenerateListApprovalsSummariesRequest) (*guardianv1beta1.GenerateListApprovalsSummariesResponse, error) {
	summaries, total, err := s.listApprovalsSummaries(ctx, false, req.GetRequests())
	if err != nil {
		return nil, err
	}

	return &guardianv1beta1.GenerateListApprovalsSummariesResponse{
		Summaries: summaries,
		Total:     total,
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

func (s *GRPCServer) listApprovals(ctx context.Context, filters *domain.ListApprovalsFilter) ([]*guardianv1beta1.Approval, int64, error) {
	eg, ctx := errgroup.WithContext(ctx)
	var approvals []*domain.Approval
	var total int64

	eg.Go(func() error {
		approvalRecords, err := s.approvalService.ListApprovals(ctx, filters)
		if err != nil {
			return s.internalError(ctx, "failed to get approval list: %s", err)
		}
		approvals = approvalRecords
		return nil
	})

	eg.Go(func() error {
		totalRecord, err := s.approvalService.GetApprovalsTotalCount(ctx, filters)
		if err != nil {
			return s.internalError(ctx, "failed to get approval list: %v", err)
		}
		total = totalRecord
		return nil
	})

	if err := eg.Wait(); err != nil {
		return nil, 0, err
	}

	approvalProtos := []*guardianv1beta1.Approval{}
	for _, a := range approvals {
		approvalProto, err := s.adapter.ToApprovalProto(a)
		if err != nil {
			return nil, 0, s.internalError(ctx, "failed to parse approval: %v: %s", a.ID, err)
		}
		approvalProtos = append(approvalProtos, approvalProto)
	}

	return approvalProtos, total, nil
}

func (s *GRPCServer) listApprovalsSummaries(ctx context.Context, me bool, requests map[string]*guardianv1beta1.SummaryRequest) (map[string]*guardianv1beta1.Summary, int32, error) {
	var actor string
	if me {
		u, err := s.getUser(ctx)
		if err != nil {
			return nil, 0, status.Error(codes.Unauthenticated, err.Error())
		}
		actor = u
	}

	summaries := make(map[string]*guardianv1beta1.Summary, len(requests))
	for requestKey, request := range requests {
		summaryFilter := request.GetFilter()
		groupBys := request.GetGroupBys()

		listApprovalsFilter := &domain.ListApprovalsFilter{}

		if me {
			listApprovalsFilter.CreatedBy = actor
		}

		if summaryFilter != nil {
			appealsFilter := summaryFilter.GetAppealsFilter()
			if appealsFilter != nil {
				listApprovalsFilter.AppealStatuses = appealsFilter.GetStatuses()
				listApprovalsFilter.RoleStartsWith = appealsFilter.GetRoleStartsWith()
				listApprovalsFilter.RoleEndsWith = appealsFilter.GetRoleEndsWith()
				listApprovalsFilter.RoleContains = appealsFilter.GetRoleContains()
				listApprovalsFilter.AccountTypes = appealsFilter.GetAccountTypes()
			}

			approvalsFilter := summaryFilter.GetApprovalsFilter()
			if approvalsFilter != nil {
				listApprovalsFilter.Statuses = approvalsFilter.GetStatuses()
				listApprovalsFilter.StepNames = approvalsFilter.GetStepNames()
				listApprovalsFilter.Stale = approvalsFilter.GetStale()
			}

			approversFilter := summaryFilter.GetApproversFilter()
			if approversFilter != nil {
				if !me {
					listApprovalsFilter.CreatedBy = approversFilter.Email
				}
			}
		}
		listApprovalsSummary, err := s.approvalService.GenerateListApprovalsSummary(ctx, listApprovalsFilter, groupBys)
		if err != nil {
			return nil, 0, s.internalError(ctx, "failed to generate list approvals summary: %s", err)
		}

		listApprovalsSummaryProto, err := s.adapter.ToSummaryProto(listApprovalsSummary)
		if err != nil {
			return nil, 0, s.internalError(ctx, "failed to parse summary: %v", err)
		}

		listApprovalsSummaryProto.Filter = summaryFilter
		listApprovalsSummaryProto.GroupBys = groupBys
		summaries[requestKey] = listApprovalsSummaryProto
	}

	return summaries, int32(len(summaries)), nil
}
