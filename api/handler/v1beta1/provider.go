package v1beta1

import (
	"context"
	"errors"

	"golang.org/x/sync/errgroup"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	guardianv1beta1 "github.com/goto/guardian/api/proto/gotocompany/guardian/v1beta1"
	"github.com/goto/guardian/core/provider"
	"github.com/goto/guardian/domain"
	slicesUtil "github.com/goto/guardian/pkg/slices"
)

func (s *GRPCServer) ListProviders(ctx context.Context, req *guardianv1beta1.ListProvidersRequest) (*guardianv1beta1.ListProvidersResponse, error) {
	filter := domain.ListProvidersFilter{
		Size:       int(req.GetSize()),
		Offset:     int(req.GetOffset()),
		IDs:        req.GetIds(),
		URNs:       req.GetUrns(),
		Types:      req.GetTypes(),
		FieldMasks: slicesUtil.GenericsStandardizeSliceNilAble(req.GetFieldMasks()),
	}

	providers, total, err := s.listProviders(ctx, filter)
	if err != nil {
		return nil, err
	}

	return &guardianv1beta1.ListProvidersResponse{
		Providers: providers,
		Total:     int32(total),
	}, nil
}

func (s *GRPCServer) listProviders(ctx context.Context, filter domain.ListProvidersFilter) ([]*guardianv1beta1.Provider, int64, error) {
	eg, egCtx := errgroup.WithContext(ctx)
	var providers []*domain.Provider
	var total int64

	if filter.WithProviders() {
		eg.Go(func() error {
			providerRecords, e := s.providerService.Find(egCtx, filter)
			if e != nil {
				return s.internalError(ctx, "failed to list providers: %v", e)
			}
			providers = providerRecords
			return nil
		})
	}

	if filter.WithTotal() {
		eg.Go(func() error {
			totalRecord, e := s.providerService.GetCount(egCtx, filter)
			if e != nil {
				return s.internalError(ctx, "failed to get providers count: %v", e)
			}
			total = totalRecord
			return nil
		})
	}

	if err := eg.Wait(); err != nil {
		return nil, 0, err
	}

	providerProtos := []*guardianv1beta1.Provider{}
	for _, p := range providers {
		p.Config.Credentials = nil
		providerProto, err := s.adapter.ToProviderProto(p)
		if err != nil {
			return nil, 0, s.internalError(ctx, "failed to parse provider %s: %v", p.URN, err)
		}
		providerProtos = append(providerProtos, providerProto)
	}

	return providerProtos, total, nil
}

func (s *GRPCServer) GetProvider(ctx context.Context, req *guardianv1beta1.GetProviderRequest) (*guardianv1beta1.GetProviderResponse, error) {
	p, err := s.providerService.GetByID(ctx, req.GetId())
	if err != nil {
		switch err {
		case provider.ErrRecordNotFound:
			return nil, status.Error(codes.NotFound, "provider not found")
		default:
			return nil, s.internalError(ctx, "failed to retrieve provider: %v", err)
		}
	}

	providerProto, err := s.adapter.ToProviderProto(p)
	if err != nil {
		return nil, s.internalError(ctx, "failed to parse provider %s: %v", p.URN, err)
	}

	return &guardianv1beta1.GetProviderResponse{
		Provider: providerProto,
	}, nil
}

func (s *GRPCServer) GetProviderTypes(ctx context.Context, req *guardianv1beta1.GetProviderTypesRequest) (*guardianv1beta1.GetProviderTypesResponse, error) {
	providerTypes, err := s.providerService.GetTypes(ctx)
	if err != nil {
		return nil, s.internalError(ctx, "failed to retrieve provider types: %v", err)
	}

	var providerTypeProtos []*guardianv1beta1.ProviderType
	for _, pt := range providerTypes {
		providerTypeProtos = append(providerTypeProtos, s.adapter.ToProviderTypeProto(pt))
	}

	return &guardianv1beta1.GetProviderTypesResponse{
		ProviderTypes: providerTypeProtos,
	}, nil
}

func (s *GRPCServer) CreateProvider(ctx context.Context, req *guardianv1beta1.CreateProviderRequest) (*guardianv1beta1.CreateProviderResponse, error) {
	if req.GetDryRun() {
		ctx = provider.WithDryRun(ctx)
	}

	providerConfig := s.adapter.FromProviderConfigProto(req.GetConfig())
	p := &domain.Provider{
		Type:   providerConfig.Type,
		URN:    providerConfig.URN,
		Config: providerConfig,
	}

	if err := s.providerService.Create(ctx, p); err != nil {
		switch {
		case errors.Is(err, provider.ErrInvalidProviderConfig):
			return nil, s.invalidArgument(ctx, "%s", err.Error())
		default:
			s.logger.Error(ctx, "failed to create provider", "provider_urn", p.URN, "type", p.Type, "error", err)
			return nil, s.internalError(ctx, "failed to create provider: %v", err)
		}
	}

	providerProto, err := s.adapter.ToProviderProto(p)
	if err != nil {
		return nil, s.internalError(ctx, "failed to parse provider: %v", err)
	}

	return &guardianv1beta1.CreateProviderResponse{
		Provider: providerProto,
	}, nil
}

func (s *GRPCServer) UpdateProvider(ctx context.Context, req *guardianv1beta1.UpdateProviderRequest) (*guardianv1beta1.UpdateProviderResponse, error) {
	if req.GetDryRun() {
		ctx = provider.WithDryRun(ctx)
	}

	id := req.GetId()
	providerConfig := s.adapter.FromProviderConfigProto(req.GetConfig())
	p := &domain.Provider{
		ID:     id,
		Type:   providerConfig.Type,
		URN:    providerConfig.URN,
		Config: providerConfig,
	}

	if err := s.providerService.Update(ctx, p); err != nil {
		s.logger.Error(ctx, "failed to update provider", "provider_id", id, "provider_urn", p.URN, "type", p.Type, "error", err)
		return nil, s.internalError(ctx, "failed to update provider: %v", err)
	}

	providerProto, err := s.adapter.ToProviderProto(p)
	if err != nil {
		return nil, s.internalError(ctx, "failed to parse provider: %v", err)
	}

	return &guardianv1beta1.UpdateProviderResponse{
		Provider: providerProto,
	}, nil
}

func (s *GRPCServer) DeleteProvider(ctx context.Context, req *guardianv1beta1.DeleteProviderRequest) (*guardianv1beta1.DeleteProviderResponse, error) {
	if err := s.providerService.Delete(ctx, req.GetId()); err != nil {
		if errors.Is(err, provider.ErrRecordNotFound) {
			return nil, status.Errorf(codes.NotFound, "provider not found")
		}
		return nil, s.internalError(ctx, "failed to delete provider: %v", err)
	}

	return &guardianv1beta1.DeleteProviderResponse{}, nil
}

func (s *GRPCServer) ListRoles(ctx context.Context, req *guardianv1beta1.ListRolesRequest) (*guardianv1beta1.ListRolesResponse, error) {
	roles, err := s.providerService.GetRoles(ctx, req.GetId(), req.GetResourceType())
	if err != nil {
		return nil, s.internalError(ctx, "failed to list roles: %v", err)
	}

	roleProtos := []*guardianv1beta1.Role{}
	for _, r := range roles {
		role, err := s.adapter.ToRole(r)
		if err != nil {
			return nil, s.internalError(ctx, "failed to parse proto: %v", err)
		}

		roleProtos = append(roleProtos, role)
	}

	return &guardianv1beta1.ListRolesResponse{
		Roles: roleProtos,
	}, nil
}
