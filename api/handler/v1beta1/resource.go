package v1beta1

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/sync/errgroup"

	"github.com/google/uuid"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	guardianv1beta1 "github.com/goto/guardian/api/proto/gotocompany/guardian/v1beta1"
	"github.com/goto/guardian/core/provider"
	"github.com/goto/guardian/core/resource"
	"github.com/goto/guardian/domain"
)

func (s *GRPCServer) CreateResource(ctx context.Context, req *guardianv1beta1.CreateResourceRequest) (*guardianv1beta1.CreateResourceResponse, error) {
	r := s.adapter.FromResourceProto(req.GetResource())

	if err := s.providerService.CreateResource(ctx, r); err != nil {
		switch {
		case errors.Is(err, provider.ErrRecordNotFound):
			return nil, s.notFound(ctx, fmt.Sprintf("provider with type %q and urn %q does not exist", r.ProviderType, r.ProviderURN))
		case errors.Is(err, provider.ErrInvalidResourceType),
			errors.Is(err, provider.ErrInvalidResource),
			errors.Is(err, resource.ErrInvalidResource):
			return nil, s.invalidArgument(ctx, err.Error())
		case errors.Is(err, provider.ErrCreateResourceNotSupported):
			return nil, s.failedPrecondition(ctx, err.Error())
		case errors.Is(err, resource.ErrResourceAlreadyExists):
			return nil, s.alreadyExists(ctx, err.Error())
		default:
			return nil, s.internalError(ctx, err.Error())
		}
	}

	resourceProto, err := s.adapter.ToResourceProto(r)
	if err != nil {
		return nil, s.internalError(ctx, "failed to convert to resource proto: %v", err)
	}

	return &guardianv1beta1.CreateResourceResponse{
		Resource: resourceProto,
	}, nil
}

func (s *GRPCServer) ListResources(ctx context.Context, req *guardianv1beta1.ListResourcesRequest) (*guardianv1beta1.ListResourcesResponse, error) {
	var details map[string]string
	if req.GetDetails() != nil {
		details = map[string]string{}
		for _, d := range req.GetDetails() {
			filter := strings.SplitN(d, ":", 2)
			if len(filter) == 2 {
				path := filter[0]
				value := filter[1]
				details[path] = value
			}
		}
	}
	filter := domain.ListResourcesFilter{
		IsDeleted:     req.GetIsDeleted(),
		ProviderType:  req.GetProviderType(),
		ProviderURN:   req.GetProviderUrn(),
		ProviderTypes: req.GetProviderTypes(),
		ProviderURNs:  req.GetProviderUrns(),
		Name:          req.GetName(),
		ResourceURN:   req.GetUrn(),
		ResourceType:  req.GetType(),
		ResourceURNs:  req.GetUrns(),
		ResourceTypes: req.GetTypes(),
		Details:       details,
		Size:          req.GetSize(),
		Offset:        req.GetOffset(),
		OrderBy:       req.GetOrderBy(),
		Q:             req.GetQ(),
		GroupIDs:      req.GetGroupIds(),
		GroupTypes:    req.GetGroupTypes(),
	}

	resources, total, err := s.listResources(ctx, filter)
	if err != nil {
		return nil, err
	}

	return &guardianv1beta1.ListResourcesResponse{
		Resources: resources,
		Total:     uint32(total),
	}, nil
}

func (s *GRPCServer) listResources(ctx context.Context, filter domain.ListResourcesFilter) ([]*guardianv1beta1.Resource, int64, error) {
	eg, ctx := errgroup.WithContext(ctx)
	var resources []*domain.Resource
	var total int64

	eg.Go(func() error {
		resourceRecords, err := s.resourceService.Find(ctx, filter)
		if err != nil {
			return s.internalError(ctx, "failed to get resource list: %s", err)
		}
		resources = resourceRecords
		return nil
	})
	eg.Go(func() error {
		totalRecord, err := s.resourceService.GetResourcesTotalCount(ctx, filter)
		if err != nil {
			return s.internalError(ctx, "failed to get resource total count: %s", err)
		}
		total = totalRecord
		return nil
	})

	if err := eg.Wait(); err != nil {
		return nil, 0, err
	}
	var resourceProtos []*guardianv1beta1.Resource
	for i, r := range resources {
		resourceProto, err := s.adapter.ToResourceProto(resources[i])
		if err != nil {
			return nil, 0, s.internalError(ctx, "failed to parse resource %v: %v", r.Name, err)
		}
		resourceProtos = append(resourceProtos, resourceProto)
	}

	return resourceProtos, total, nil
}

func (s *GRPCServer) GetResource(ctx context.Context, req *guardianv1beta1.GetResourceRequest) (*guardianv1beta1.GetResourceResponse, error) {
	r, err := s.resourceService.GetOne(ctx, req.GetId())
	if err != nil {
		switch err {
		case resource.ErrRecordNotFound:
			return nil, status.Error(codes.NotFound, "resource not found")
		default:
			return nil, s.internalError(ctx, "failed to retrieve resource: %v", err)
		}
	}

	resourceProto, err := s.adapter.ToResourceProto(r)
	if err != nil {
		return nil, s.internalError(ctx, "failed to parse resource: %v", err)
	}

	return &guardianv1beta1.GetResourceResponse{
		Resource: resourceProto,
	}, nil
}

func (s *GRPCServer) UpdateResource(ctx context.Context, req *guardianv1beta1.UpdateResourceRequest) (*guardianv1beta1.UpdateResourceResponse, error) {
	r := s.adapter.FromResourceProto(req.GetResource())

	if _, err := uuid.Parse(req.GetId()); err != nil {
		r.GlobalURN = req.GetId()
	} else {
		r.ID = req.GetId()
	}

	if err := s.providerService.PatchResource(ctx, r); err != nil {
		if errors.Is(err, resource.ErrRecordNotFound) {
			return nil, status.Error(codes.NotFound, "resource not found")
		}
		return nil, s.internalError(ctx, "failed to update resource: %v", err)
	}

	resourceProto, err := s.adapter.ToResourceProto(r)
	if err != nil {
		return nil, s.internalError(ctx, "failed to parse resource: %v", err)
	}

	return &guardianv1beta1.UpdateResourceResponse{
		Resource: resourceProto,
	}, nil
}

func (s *GRPCServer) DeleteResource(ctx context.Context, req *guardianv1beta1.DeleteResourceRequest) (*guardianv1beta1.DeleteResourceResponse, error) {
	if err := s.resourceService.Delete(ctx, req.GetId()); err != nil {
		if errors.Is(err, resource.ErrRecordNotFound) {
			return nil, status.Errorf(codes.NotFound, "resource not found")
		}
		return nil, s.internalError(ctx, "failed to update resource: %v", err)
	}

	return &guardianv1beta1.DeleteResourceResponse{}, nil
}
