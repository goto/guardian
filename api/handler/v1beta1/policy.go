package v1beta1

import (
	"context"
	"errors"

	guardianv1beta1 "github.com/goto/guardian/api/proto/gotocompany/guardian/v1beta1"
	"github.com/goto/guardian/core/policy"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func (s *GRPCServer) ListPolicies(ctx context.Context, req *guardianv1beta1.ListPoliciesRequest) (*guardianv1beta1.ListPoliciesResponse, error) {
	policies, err := s.policyService.Find(ctx)
	if err != nil {
		return nil, s.internalError(ctx, "failed to get policy list: %v", err)
	}

	policyProtos := []*guardianv1beta1.Policy{}
	for _, p := range policies {
		p.RemoveSensitiveValues()
		policyProto, err := s.adapter.ToPolicyProto(p)
		if err != nil {
			return nil, s.internalError(ctx, "failed to parse policy %v: %v", p.ID, err)
		}
		policyProtos = append(policyProtos, policyProto)
	}

	return &guardianv1beta1.ListPoliciesResponse{
		Policies: policyProtos,
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
