package v1beta1

import (
	"context"
	"errors"

	guardianv1beta1 "github.com/goto/guardian/api/proto/gotocompany/guardian/v1beta1"
	"github.com/goto/guardian/core/appeal"
	"github.com/goto/guardian/core/approval"
	"github.com/goto/guardian/core/provider"
	"github.com/goto/guardian/domain"
	"golang.org/x/sync/errgroup"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func (s *GRPCServer) ListUserAppeals(ctx context.Context, req *guardianv1beta1.ListUserAppealsRequest) (*guardianv1beta1.ListUserAppealsResponse, error) {
	user, err := s.getUser(ctx)
	if err != nil {
		return nil, status.Error(codes.Unauthenticated, err.Error())
	}

	filters := &domain.ListAppealsFilter{
		CreatedBy: user,
	}
	if req.GetStatuses() != nil {
		filters.Statuses = req.GetStatuses()
	}
	if req.GetRole() != "" {
		filters.Role = req.GetRole()
	}
	if req.GetProviderTypes() != nil {
		filters.ProviderTypes = req.GetProviderTypes()
	}
	if req.GetProviderUrns() != nil {
		filters.ProviderURNs = req.GetProviderUrns()
	}
	if req.GetResourceTypes() != nil {
		filters.ResourceTypes = req.GetResourceTypes()
	}
	if req.GetAccountTypes() != nil {
		filters.AccountTypes = req.GetAccountTypes()
	}
	if req.GetResourceUrns() != nil {
		filters.ResourceURNs = req.GetResourceUrns()
	}
	if req.GetOrderBy() != nil {
		filters.OrderBy = req.GetOrderBy()
	}
	if req.GetQ() != "" {
		filters.Q = req.GetQ()
	}
	filters.Offset = int(req.GetOffset())
	filters.Size = int(req.GetSize())

	appeals, total, err := s.listAppeals(ctx, filters)
	if err != nil {
		return nil, err
	}

	return &guardianv1beta1.ListUserAppealsResponse{
		Appeals: appeals,
		Total:   int32(total),
	}, nil
}

func (s *GRPCServer) ListAppeals(ctx context.Context, req *guardianv1beta1.ListAppealsRequest) (*guardianv1beta1.ListAppealsResponse, error) {
	filters := &domain.ListAppealsFilter{
		Q:             req.GetQ(),
		AccountTypes:  req.GetAccountTypes(),
		AccountID:     req.GetAccountId(),
		Statuses:      req.GetStatuses(),
		Role:          req.GetRole(),
		ProviderTypes: req.GetProviderTypes(),
		ProviderURNs:  req.GetProviderUrns(),
		ResourceTypes: req.GetResourceTypes(),
		ResourceURNs:  req.GetResourceUrns(),
		Size:          int(req.GetSize()),
		Offset:        int(req.GetOffset()),
		OrderBy:       req.GetOrderBy(),
	}
	appeals, total, err := s.listAppeals(ctx, filters)
	if err != nil {
		return nil, err
	}

	return &guardianv1beta1.ListAppealsResponse{
		Appeals: appeals,
		Total:   int32(total),
	}, nil
}

func (s *GRPCServer) CreateAppeal(ctx context.Context, req *guardianv1beta1.CreateAppealRequest) (*guardianv1beta1.CreateAppealResponse, error) {
	authenticatedUser, err := s.getUser(ctx)
	if err != nil {
		return nil, status.Error(codes.Unauthenticated, err.Error())
	}

	appeals, err := s.adapter.FromCreateAppealProto(req, authenticatedUser)
	if err != nil {
		return nil, s.internalError(ctx, "cannot deserialize payload: %v", err)
	}

	if err := s.appealService.Create(ctx, appeals); err != nil {
		switch {
		case errors.Is(err, provider.ErrAppealValidationInvalidAccountType),
			errors.Is(err, provider.ErrAppealValidationInvalidRole),
			errors.Is(err, provider.ErrAppealValidationDurationNotSpecified),
			errors.Is(err, provider.ErrAppealValidationEmptyDuration),
			errors.Is(err, provider.ErrAppealValidationInvalidDurationValue),
			errors.Is(err, provider.ErrAppealValidationMissingRequiredParameter),
			errors.Is(err, provider.ErrAppealValidationMissingRequiredQuestion),
			errors.Is(err, appeal.ErrDurationNotAllowed),
			errors.Is(err, appeal.ErrCannotCreateAppealForOtherUser):
			return nil, s.invalidArgument(ctx, err.Error())
		case errors.Is(err, appeal.ErrAppealDuplicate):
			s.logger.Error(ctx, err.Error())
			return nil, status.Errorf(codes.AlreadyExists, err.Error())
		case errors.Is(err, appeal.ErrResourceNotFound),
			errors.Is(err, appeal.ErrResourceDeleted),
			errors.Is(err, appeal.ErrProviderNotFound),
			errors.Is(err, appeal.ErrPolicyNotFound),
			errors.Is(err, appeal.ErrInvalidResourceType),
			errors.Is(err, appeal.ErrAppealInvalidExtensionDuration),
			errors.Is(err, appeal.ErrGrantNotEligibleForExtension),
			errors.Is(err, domain.ErrFailedToGetApprovers),
			errors.Is(err, domain.ErrApproversNotFound),
			errors.Is(err, domain.ErrUnexpectedApproverType),
			errors.Is(err, domain.ErrInvalidApproverValue):
			return nil, s.failedPrecondition(ctx, err.Error())
		default:
			return nil, s.internalError(ctx, "failed to create appeal(s): %v", err)
		}
	}

	appealProtos := []*guardianv1beta1.Appeal{}
	for _, appeal := range appeals {
		appealProto, err := s.adapter.ToAppealProto(appeal)
		if err != nil {
			return nil, s.internalError(ctx, "failed to parse appeal: %v", err)
		}
		appealProtos = append(appealProtos, appealProto)
	}

	return &guardianv1beta1.CreateAppealResponse{
		Appeals: appealProtos,
	}, nil
}

func (s *GRPCServer) PatchAppeal(ctx context.Context, req *guardianv1beta1.PatchAppealRequest) (*guardianv1beta1.PatchAppealResponse, error) {
	authenticatedUser, err := s.getUser(ctx)
	if err != nil {
		return nil, status.Error(codes.Unauthenticated, err.Error())
	}

	if req.Id == "" {
		return nil, status.Error(codes.FailedPrecondition, "appeal id is required")
	}

	a, err := s.adapter.FromPatchAppealProto(req, authenticatedUser)
	if err != nil {
		return nil, s.internalError(ctx, "cannot deserialize payload: %v", err)
	}

	if err := s.appealService.Patch(ctx, a); err != nil {
		switch {
		case errors.Is(err, provider.ErrAppealValidationInvalidAccountType),
			errors.Is(err, provider.ErrAppealValidationInvalidRole),
			errors.Is(err, provider.ErrAppealValidationDurationNotSpecified),
			errors.Is(err, provider.ErrAppealValidationEmptyDuration),
			errors.Is(err, provider.ErrAppealValidationInvalidDurationValue),
			errors.Is(err, provider.ErrAppealValidationMissingRequiredParameter),
			errors.Is(err, provider.ErrAppealValidationMissingRequiredQuestion),
			errors.Is(err, appeal.ErrDurationNotAllowed),
			errors.Is(err, appeal.ErrCannotCreateAppealForOtherUser):
			return nil, s.invalidArgument(ctx, err.Error())
		case errors.Is(err, appeal.ErrAppealDuplicate):
			s.logger.Error(ctx, err.Error())
			return nil, status.Errorf(codes.AlreadyExists, err.Error())
		case errors.Is(err, appeal.ErrResourceNotFound),
			errors.Is(err, appeal.ErrResourceDeleted),
			errors.Is(err, appeal.ErrProviderNotFound),
			errors.Is(err, appeal.ErrPolicyNotFound),
			errors.Is(err, appeal.ErrInvalidResourceType),
			errors.Is(err, appeal.ErrAppealInvalidExtensionDuration),
			errors.Is(err, appeal.ErrGrantNotEligibleForExtension),
			errors.Is(err, approval.ErrApprovalNotFound),
			errors.Is(err, approval.ErrApprovalIDEmptyParam),
			errors.Is(err, approval.ErrAppealIDEmptyParam),
			errors.Is(err, domain.ErrFailedToGetApprovers),
			errors.Is(err, domain.ErrApproversNotFound),
			errors.Is(err, domain.ErrUnexpectedApproverType),
			errors.Is(err, domain.ErrInvalidApproverValue),
			errors.Is(err, appeal.ErrNoChanges):
			return nil, s.failedPrecondition(ctx, err.Error())
		default:
			return nil, s.internalError(ctx, "failed to update appeal: %v", err)
		}
	}

	responseAppeal, err := s.appealService.GetByID(ctx, req.Id)
	if err != nil {
		if errors.As(err, new(appeal.InvalidError)) || errors.Is(err, appeal.ErrAppealIDEmptyParam) {
			return nil, s.invalidArgument(ctx, err.Error())
		}
		return nil, s.internalError(ctx, "failed to retrieve appeal: %v", err)
	}

	appealProto, err := s.adapter.ToAppealProto(responseAppeal)
	if err != nil {
		return nil, s.internalError(ctx, "failed to parse appeal: %v", err)
	}

	return &guardianv1beta1.PatchAppealResponse{
		Appeal: appealProto,
	}, nil
}

func (s *GRPCServer) GetAppeal(ctx context.Context, req *guardianv1beta1.GetAppealRequest) (*guardianv1beta1.GetAppealResponse, error) {
	id := req.GetId()

	a, err := s.appealService.GetByID(ctx, id)
	if err != nil {
		if errors.As(err, new(appeal.InvalidError)) || errors.Is(err, appeal.ErrAppealIDEmptyParam) {
			return nil, s.invalidArgument(ctx, err.Error())
		}
		return nil, s.internalError(ctx, "failed to retrieve appeal: %v", err)
	}

	if a == nil {
		return nil, status.Errorf(codes.NotFound, "appeal not found: %v", id)
	}

	appealProto, err := s.adapter.ToAppealProto(a)
	if err != nil {
		return nil, s.internalError(ctx, "failed to parse appeal: %v", err)
	}

	return &guardianv1beta1.GetAppealResponse{
		Appeal: appealProto,
	}, nil
}

func (s *GRPCServer) CancelAppeal(ctx context.Context, req *guardianv1beta1.CancelAppealRequest) (*guardianv1beta1.CancelAppealResponse, error) {
	id := req.GetId()

	a, err := s.appealService.Cancel(ctx, id)
	if err != nil {
		if errors.As(err, new(appeal.InvalidError)) || errors.Is(err, appeal.ErrAppealIDEmptyParam) {
			return nil, s.invalidArgument(ctx, err.Error())
		}

		switch err {
		case appeal.ErrAppealNotFound:
			return nil, status.Errorf(codes.NotFound, "appeal not found: %v", id)
		case appeal.ErrAppealStatusCanceled,
			appeal.ErrAppealStatusApproved,
			appeal.ErrAppealStatusRejected,
			appeal.ErrAppealStatusUnrecognized:
			return nil, s.invalidArgument(ctx, "unable to process the request: %v", err)
		default:
			return nil, s.internalError(ctx, "failed to cancel appeal: %v", err)
		}
	}

	appealProto, err := s.adapter.ToAppealProto(a)
	if err != nil {
		return nil, s.internalError(ctx, "failed to parse appeal: %v", err)
	}

	return &guardianv1beta1.CancelAppealResponse{
		Appeal: appealProto,
	}, nil
}

func (s *GRPCServer) ListAppealActivities(ctx context.Context, req *guardianv1beta1.ListAppealActivitiesRequest) (*guardianv1beta1.ListAppealActivitiesResponse, error) {
	activities, err := s.appealService.ListActivities(ctx, req.GetAppealId())
	if err != nil {
		return nil, s.internalError(ctx, "failed to get appeal activities: %v", err)
	}

	activityProtos := make([]*guardianv1beta1.AppealActivity, 0, len(activities))
	for _, a := range activities {
		activityProto, err := s.adapter.ToAppealActivityProto(a)
		if err != nil {
			return nil, s.internalError(ctx, "failed to parse appeal activity: %v", err)
		}
		activityProtos = append(activityProtos, activityProto)
	}

	return &guardianv1beta1.ListAppealActivitiesResponse{
		Activities: activityProtos,
	}, nil
}

func (s *GRPCServer) listAppeals(ctx context.Context, filters *domain.ListAppealsFilter) ([]*guardianv1beta1.Appeal, int64, error) {
	eg, ctx := errgroup.WithContext(ctx)
	var appeals []*domain.Appeal
	var total int64

	eg.Go(func() error {
		appealRecords, err := s.appealService.Find(ctx, filters)
		if err != nil {
			return s.internalError(ctx, "failed to get appeal list: %s", err)
		}
		appeals = appealRecords
		return nil
	})
	eg.Go(func() error {
		totalRecord, err := s.appealService.GetAppealsTotalCount(ctx, filters)
		if err != nil {
			return s.internalError(ctx, "failed to get appeal total count: %s", err)
		}
		total = totalRecord
		return nil
	})

	if err := eg.Wait(); err != nil {
		return nil, 0, err
	}

	appealProtos := []*guardianv1beta1.Appeal{}
	for _, a := range appeals {
		appealProto, err := s.adapter.ToAppealProto(a)
		if err != nil {
			return nil, 0, s.internalError(ctx, "failed to parse appeal: %s", err)
		}
		appealProtos = append(appealProtos, appealProto)
	}

	return appealProtos, total, nil
}
