package v1beta1

import (
	"context"
	"errors"

	"golang.org/x/sync/errgroup"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	guardianv1beta1 "github.com/goto/guardian/api/proto/gotocompany/guardian/v1beta1"
	"github.com/goto/guardian/core/appeal"
	"github.com/goto/guardian/core/approval"
	"github.com/goto/guardian/core/provider"
	"github.com/goto/guardian/domain"
	slicesUtil "github.com/goto/guardian/pkg/slices"
)

func (s *GRPCServer) ListUserAppeals(ctx context.Context, req *guardianv1beta1.ListUserAppealsRequest) (*guardianv1beta1.ListUserAppealsResponse, error) {
	user, err := s.getUser(ctx)
	if err != nil {
		return nil, status.Error(codes.Unauthenticated, err.Error())
	}

	// Extract labels from gRPC metadata
	labels, err := s.extractLabels(ctx)
	if err != nil {
		return nil, s.internalError(ctx, "failed to extract labels from gRPC metadata: %v", err)
	}

	// Fallback to proto labels if no metadata labels found
	if len(labels) == 0 {
		labels = s.adapter.FromLabelFiltersProto(req.GetLabels())
	}

	filters := &domain.ListAppealsFilter{
		Q:                         req.GetQ(),
		AccountTypes:              req.GetAccountTypes(),
		CreatedBy:                 user,
		AccountIDs:                req.GetAccountIds(),
		GroupIDs:                  req.GetGroupIds(),
		GroupTypes:                req.GetGroupTypes(),
		Role:                      req.GetRole(),
		Roles:                     req.GetRoles(),
		Statuses:                  req.GetStatuses(),
		ProviderTypes:             req.GetProviderTypes(),
		ProviderURNs:              req.GetProviderUrns(),
		ResourceTypes:             req.GetResourceTypes(),
		ResourceURNs:              req.GetResourceUrns(),
		OrderBy:                   req.GetOrderBy(),
		Size:                      int(req.GetSize()),
		Offset:                    int(req.GetOffset()),
		ResourceIDs:               req.GetResourceIds(),
		SummaryGroupBys:           slicesUtil.GenericsStandardizeSliceNilAble(req.GetSummaryGroupBys()),
		SummaryUniques:            slicesUtil.GenericsStandardizeSliceNilAble(req.GetSummaryUniques()),
		FieldMasks:                slicesUtil.GenericsStandardizeSliceNilAble(req.GetFieldMasks()),
		RoleStartsWith:            req.GetRoleStartsWith(),
		RoleEndsWith:              req.GetRoleEndsWith(),
		RoleContains:              req.GetRoleContains(),
		StartTime:                 s.adapter.FromTimeProto(req.GetStartTime()),
		EndTime:                   s.adapter.FromTimeProto(req.GetEndTime()),
		WithApprovals:             req.GetWithApprovals(),
		ProviderUrnStartsWith:     req.GetProviderUrnStartsWith(),
		ProviderUrnEndsWith:       req.GetProviderUrnEndsWith(),
		ProviderUrnContains:       req.GetProviderUrnContains(),
		ProviderUrnNotStartsWith:  req.GetProviderUrnNotStartsWith(),
		ProviderUrnNotEndsWith:    req.GetProviderUrnNotEndsWith(),
		ProviderUrnNotContains:    req.GetProviderUrnNotContains(),
		Durations:                 req.GetDurations(),
		NotDurations:              req.GetNotDurations(),
		DetailsPaths:              req.GetDetailsPaths(),
		Details:                   req.GetDetails(),
		NotDetails:                req.GetNotDetails(),
		Labels:                    labels,
		LabelKeys:                 req.GetLabelKeys(),
		RoleNotStartsWith:         req.GetRoleNotStartsWith(),
		RoleNotEndsWith:           req.GetRoleNotEndsWith(),
		RoleNotContains:           req.GetRoleNotContains(),
		DetailsStartsWith:         req.GetDetailsStartsWith(),
		DetailsEndsWith:           req.GetDetailsEndsWith(),
		DetailsContains:           req.GetDetailsContains(),
		DetailsNotStartsWith:      req.GetDetailsNotStartsWith(),
		DetailsNotEndsWith:        req.GetDetailsNotEndsWith(),
		DetailsNotContains:        req.GetDetailsNotContains(),
		GroupTypeStartsWith:       req.GetGroupTypeStartsWith(),
		GroupTypeEndsWith:         req.GetGroupTypeEndsWith(),
		GroupTypeContains:         req.GetGroupTypeContains(),
		GroupTypeNotStartsWith:    req.GetGroupTypeNotStartsWith(),
		GroupTypeNotEndsWith:      req.GetGroupTypeNotEndsWith(),
		GroupTypeNotContains:      req.GetGroupTypeNotContains(),
		IDs:                       req.GetIds(),
		NotIDs:                    req.GetNotIds(),
		DetailsForSelfCriteria:    req.GetDetailsForSelfCriteria(),
		NotDetailsForSelfCriteria: req.GetNotDetailsForSelfCriteria(),
		SummaryLabels:             req.GetSummaryLabels(),
	}

	appeals, total, summary, err := s.listAppeals(ctx, filters)
	if err != nil {
		return nil, err
	}

	return &guardianv1beta1.ListUserAppealsResponse{
		Appeals: appeals,
		Total:   int32(total),
		Summary: summary,
	}, nil
}

func (s *GRPCServer) ListAppeals(ctx context.Context, req *guardianv1beta1.ListAppealsRequest) (*guardianv1beta1.ListAppealsResponse, error) {
	// Extract labels from gRPC metadata
	labels, err := s.extractLabels(ctx)
	if err != nil {
		return nil, s.internalError(ctx, "failed to extract labels from gRPC metadata: %v", err)
	}

	// Fallback to proto labels if no metadata labels found
	if len(labels) == 0 {
		labels = s.adapter.FromLabelFiltersProto(req.GetLabels())
	}

	filters := &domain.ListAppealsFilter{
		Q:                         req.GetQ(),
		AccountTypes:              req.GetAccountTypes(),
		CreatedBy:                 req.GetCreatedBy(),
		AccountID:                 req.GetAccountId(),
		AccountIDs:                req.GetAccountIds(),
		GroupIDs:                  req.GetGroupIds(),
		GroupTypes:                req.GetGroupTypes(),
		Role:                      req.GetRole(),
		Roles:                     req.GetRoles(),
		Statuses:                  req.GetStatuses(),
		ProviderTypes:             req.GetProviderTypes(),
		ProviderURNs:              req.GetProviderUrns(),
		ResourceTypes:             req.GetResourceTypes(),
		ResourceURNs:              req.GetResourceUrns(),
		OrderBy:                   req.GetOrderBy(),
		Size:                      int(req.GetSize()),
		Offset:                    int(req.GetOffset()),
		ResourceIDs:               req.GetResourceIds(),
		SummaryGroupBys:           slicesUtil.GenericsStandardizeSliceNilAble(req.GetSummaryGroupBys()),
		SummaryUniques:            slicesUtil.GenericsStandardizeSliceNilAble(req.GetSummaryUniques()),
		FieldMasks:                slicesUtil.GenericsStandardizeSliceNilAble(req.GetFieldMasks()),
		RoleStartsWith:            req.GetRoleStartsWith(),
		RoleEndsWith:              req.GetRoleEndsWith(),
		RoleContains:              req.GetRoleContains(),
		StartTime:                 s.adapter.FromTimeProto(req.GetStartTime()),
		EndTime:                   s.adapter.FromTimeProto(req.GetEndTime()),
		WithApprovals:             req.GetWithApprovals(),
		ProviderUrnStartsWith:     req.GetProviderUrnStartsWith(),
		ProviderUrnEndsWith:       req.GetProviderUrnEndsWith(),
		ProviderUrnContains:       req.GetProviderUrnContains(),
		ProviderUrnNotStartsWith:  req.GetProviderUrnNotStartsWith(),
		ProviderUrnNotEndsWith:    req.GetProviderUrnNotEndsWith(),
		ProviderUrnNotContains:    req.GetProviderUrnNotContains(),
		Durations:                 req.GetDurations(),
		NotDurations:              req.GetNotDurations(),
		DetailsPaths:              req.GetDetailsPaths(),
		Details:                   req.GetDetails(),
		NotDetails:                req.GetNotDetails(),
		Labels:                    labels,
		LabelKeys:                 req.GetLabelKeys(),
		RoleNotStartsWith:         req.GetRoleNotStartsWith(),
		RoleNotEndsWith:           req.GetRoleNotEndsWith(),
		RoleNotContains:           req.GetRoleNotContains(),
		DetailsStartsWith:         req.GetDetailsStartsWith(),
		DetailsEndsWith:           req.GetDetailsEndsWith(),
		DetailsContains:           req.GetDetailsContains(),
		DetailsNotStartsWith:      req.GetDetailsNotStartsWith(),
		DetailsNotEndsWith:        req.GetDetailsNotEndsWith(),
		DetailsNotContains:        req.GetDetailsNotContains(),
		GroupTypeStartsWith:       req.GetGroupTypeStartsWith(),
		GroupTypeEndsWith:         req.GetGroupTypeEndsWith(),
		GroupTypeContains:         req.GetGroupTypeContains(),
		GroupTypeNotStartsWith:    req.GetGroupTypeNotStartsWith(),
		GroupTypeNotEndsWith:      req.GetGroupTypeNotEndsWith(),
		GroupTypeNotContains:      req.GetGroupTypeNotContains(),
		IDs:                       req.GetIds(),
		NotIDs:                    req.GetNotIds(),
		DetailsForSelfCriteria:    req.GetDetailsForSelfCriteria(),
		NotDetailsForSelfCriteria: req.GetNotDetailsForSelfCriteria(),
		SummaryLabels:             req.GetSummaryLabels(),
	}

	appeals, total, summary, err := s.listAppeals(ctx, filters)
	if err != nil {
		return nil, err
	}

	return &guardianv1beta1.ListAppealsResponse{
		Appeals: appeals,
		Total:   int32(total),
		Summary: summary,
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

	var createOpts []appeal.CreateAppealOption
	if req.GetDryRun() {
		createOpts = append(createOpts, appeal.CreateWithDryRun())
	}

	if err := s.appealService.Create(ctx, appeals, createOpts...); err != nil {
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
			return nil, s.invalidArgument(ctx, "%s", err.Error())
		case errors.Is(err, appeal.ErrAppealDuplicate):
			s.logger.Error(ctx, err.Error())
			return nil, status.Errorf(codes.AlreadyExists, "%s", err.Error())
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
			return nil, s.failedPrecondition(ctx, "%s", err.Error())
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
		DryRun:  req.GetDryRun(),
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
			return nil, s.invalidArgument(ctx, "%s", err.Error())
		case errors.Is(err, appeal.ErrAppealDuplicate):
			s.logger.Error(ctx, err.Error())
			return nil, status.Errorf(codes.AlreadyExists, "%s", err.Error())
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
			return nil, s.failedPrecondition(ctx, "%s", err.Error())
		default:
			return nil, s.internalError(ctx, "failed to update appeal: %v", err)
		}
	}

	responseAppeal, err := s.appealService.GetByID(ctx, req.Id)
	if err != nil {
		if errors.As(err, new(appeal.InvalidError)) || errors.Is(err, appeal.ErrAppealIDEmptyParam) {
			return nil, s.invalidArgument(ctx, "%s", err.Error())
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
			return nil, s.invalidArgument(ctx, "%s", err.Error())
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
			return nil, s.invalidArgument(ctx, "%s", err.Error())
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

func (s *GRPCServer) listAppeals(ctx context.Context, filters *domain.ListAppealsFilter) ([]*guardianv1beta1.Appeal, int64, *guardianv1beta1.SummaryResult, error) {
	eg, ctx := errgroup.WithContext(ctx)
	var appeals []*domain.Appeal
	var summary *domain.SummaryResult
	var total int64

	if filters.WithAppeals() {
		eg.Go(func() error {
			appealRecords, err := s.appealService.Find(ctx, filters)
			if err != nil {
				return s.internalError(ctx, "failed to get appeal list: %s", err)
			}
			appeals = appealRecords
			return nil
		})
	}
	if filters.WithTotal() {
		eg.Go(func() error {
			totalRecord, err := s.appealService.GetAppealsTotalCount(ctx, filters)
			if err != nil {
				return s.internalError(ctx, "failed to get appeal total count: %s", err)
			}
			total = totalRecord
			return nil
		})
	}
	if filters.WithSummary() {
		eg.Go(func() error {
			var e error
			summary, e = s.appealService.GenerateSummary(ctx, filters)
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

	appealsProto := make([]*guardianv1beta1.Appeal, len(appeals))
	for i, a := range appeals {
		appealProto, err := s.adapter.ToAppealProto(a)
		if err != nil {
			return nil, 0, nil, s.internalError(ctx, "failed to parse appeal: %s", err)
		}
		appealsProto[i] = appealProto
	}

	summaryProto, err := s.adapter.ToSummaryProto(summary)
	if err != nil {
		return nil, 0, nil, s.internalError(ctx, "failed to parse summary: %v", err)
	}

	return appealsProto, total, summaryProto, nil
}
