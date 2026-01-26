package v1beta1

import (
	"context"
	"errors"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"golang.org/x/sync/errgroup"

	guardianv1beta1 "github.com/goto/guardian/api/proto/gotocompany/guardian/v1beta1"
	"github.com/goto/guardian/core/policy"
	"github.com/goto/guardian/domain"
	slicesUtil "github.com/goto/guardian/pkg/slices"
)

func (s *GRPCServer) ListPolicies(ctx context.Context, req *guardianv1beta1.ListPoliciesRequest) (*guardianv1beta1.ListPoliciesResponse, error) {
	filter := domain.ListPoliciesFilter{
		Size:       int(req.GetSize()),
		Offset:     int(req.GetOffset()),
		IDs:        req.GetIds(),
		FieldMasks: slicesUtil.GenericsStandardizeSliceNilAble(req.GetFieldMasks()),
	}

	policies, total, err := s.listPolicies(ctx, filter)
	if err != nil {
		return nil, err
	}

	return &guardianv1beta1.ListPoliciesResponse{
		Policies: policies,
		Total:    int32(total),
	}, nil
}

func (s *GRPCServer) GetPolicy(ctx context.Context, req *guardianv1beta1.GetPolicyRequest) (*guardianv1beta1.GetPolicyResponse, error) {
	p, err := s.policyService.GetOne(ctx, req.GetId(), uint(req.GetVersion()))
	if err != nil {
		switch err {
		case policy.ErrPolicyNotFound:
			return nil, status.Error(codes.NotFound, "policy not found")
		default:
			return nil, s.internalError(ctx, "failed to retrieve policy: %v", err)
		}
	}

	p.RemoveSensitiveValues()
	policyProto, err := s.adapter.ToPolicyProto(p)
	if err != nil {
		return nil, s.internalError(ctx, "failed to parse policy: %v", err)
	}

	return &guardianv1beta1.GetPolicyResponse{
		Policy: policyProto,
	}, nil
}

func (s *GRPCServer) CreatePolicy(ctx context.Context, req *guardianv1beta1.CreatePolicyRequest) (*guardianv1beta1.CreatePolicyResponse, error) {
	if req.GetDryRun() {
		ctx = policy.WithDryRun(ctx)
	}

	p := s.adapter.FromPolicyProto(req.GetPolicy())

	if err := s.policyService.Create(ctx, p); err != nil {
		return nil, s.internalError(ctx, "failed to create policy: %v", err)
	}

	policyProto, err := s.adapter.ToPolicyProto(p)
	if err != nil {
		return nil, s.internalError(ctx, "failed to parse policy: %v", err)
	}

	return &guardianv1beta1.CreatePolicyResponse{
		Policy: policyProto,
	}, nil
}

func (s *GRPCServer) UpdatePolicy(ctx context.Context, req *guardianv1beta1.UpdatePolicyRequest) (*guardianv1beta1.UpdatePolicyResponse, error) {
	if req.GetDryRun() {
		ctx = policy.WithDryRun(ctx)
	}
	p := s.adapter.FromPolicyProto(req.GetPolicy())

	p.ID = req.GetId()
	if err := s.policyService.Update(ctx, p); err != nil {
		if errors.Is(err, policy.ErrPolicyNotFound) {
			return nil, status.Error(codes.NotFound, "policy not found")
		} else if errors.Is(err, policy.ErrEmptyIDParam) {
			return nil, status.Error(codes.InvalidArgument, err.Error())
		}

		return nil, s.internalError(ctx, "failed to update policy: %v", err)
	}

	policyProto, err := s.adapter.ToPolicyProto(p)
	if err != nil {
		return nil, s.internalError(ctx, "failed to parse policy: %v", err)
	}

	return &guardianv1beta1.UpdatePolicyResponse{
		Policy: policyProto,
	}, nil
}

func (s *GRPCServer) GetPolicyPreferences(ctx context.Context, req *guardianv1beta1.GetPolicyPreferencesRequest) (*guardianv1beta1.GetPolicyPreferencesResponse, error) {
	p, err := s.policyService.GetOne(ctx, req.GetId(), uint(req.GetVersion()))
	if err != nil {
		switch err {
		case policy.ErrPolicyNotFound:
			return nil, status.Error(codes.NotFound, "policy not found")
		default:
			return nil, s.internalError(ctx, "failed to retrieve policy: %v", err)
		}
	}

	p.RemoveSensitiveValues()
	appealConfigProto, err := s.adapter.ToPolicyAppealConfigProto(p)
	if err != nil {
		return nil, s.internalError(ctx, "failed to parse policy preferences: %v", err)
	}

	return &guardianv1beta1.GetPolicyPreferencesResponse{
		Appeal: appealConfigProto,
	}, nil
}

func (s *GRPCServer) listPolicies(ctx context.Context, filter domain.ListPoliciesFilter) ([]*guardianv1beta1.Policy, int64, error) {
	eg, egCtx := errgroup.WithContext(ctx)
	var policies []*domain.Policy
	var total int64

	if filter.WithPolicies() {
		eg.Go(func() error {
			policyRecords, e := s.policyService.Find(egCtx, filter)
			if e != nil {
				return s.internalError(ctx, "failed to get policy list: %v", e)
			}
			policies = policyRecords
			return nil
		})
	}

	if filter.WithTotal() {
		eg.Go(func() error {
			totalRecord, e := s.policyService.GetCount(egCtx, filter)
			if e != nil {
				return s.internalError(ctx, "failed to get policies count: %v", e)
			}
			total = totalRecord
			return nil
		})
	}

	if err := eg.Wait(); err != nil {
		return nil, 0, err
	}

	policiesProto := []*guardianv1beta1.Policy{}
	for _, p := range policies {
		p.RemoveSensitiveValues()
		policyProto, err := s.adapter.ToPolicyProto(p)
		if err != nil {
			return nil, 0, s.internalError(ctx, "failed to parse policy %v: %v", p.ID, err)
		}
		policiesProto = append(policiesProto, policyProto)
	}

	return policiesProto, total, nil
}
