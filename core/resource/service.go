package resource

import (
	"context"

	"github.com/goto/guardian/domain"
	"github.com/goto/guardian/pkg/log"
	"github.com/imdario/mergo"
)

const (
	AuditKeyResoruceBulkUpsert  = "resource.bulkUpsert"
	AuditKeyResourceUpdate      = "resource.update"
	AuditKeyResourceDelete      = "resource.delete"
	AuditKeyResourceBatchDelete = "resource.batchDelete"

	ReservedDetailsKeyMetadata = "__metadata"
)

//go:generate mockery --name=repository --exported --with-expecter
type repository interface {
	Find(context.Context, domain.ListResourcesFilter) ([]*domain.Resource, error)
	GetOne(ctx context.Context, id string) (*domain.Resource, error)
	BulkUpsert(context.Context, []*domain.Resource) error
	Update(context.Context, *domain.Resource) error
	Delete(ctx context.Context, id string) error
	BatchDelete(context.Context, []string) error
	GetResourcesTotalCount(context.Context, domain.ListResourcesFilter) (int64, error)
}

//go:generate mockery --name=auditLogger --exported --with-expecter
type auditLogger interface {
	Log(ctx context.Context, action string, data interface{}) error
}

// Service handles the business logic for resource
type Service struct {
	repo repository

	logger      log.Logger
	auditLogger auditLogger
}

type ServiceDeps struct {
	Repository repository

	Logger      log.Logger
	AuditLogger auditLogger
}

// NewService returns *Service
func NewService(deps ServiceDeps) *Service {
	return &Service{
		deps.Repository,

		deps.Logger,
		deps.AuditLogger,
	}
}

// Find records based on filters
func (s *Service) Find(ctx context.Context, filter domain.ListResourcesFilter) ([]*domain.Resource, error) {
	return s.repo.Find(ctx, filter)
}

func (s *Service) GetOne(ctx context.Context, id string) (*domain.Resource, error) {
	r, err := s.repo.GetOne(ctx, id)
	if err != nil {
		return nil, err
	}

	return r, nil
}

// BulkUpsert inserts or updates records
func (s *Service) BulkUpsert(ctx context.Context, resources []*domain.Resource) error {
	if err := s.repo.BulkUpsert(ctx, resources); err != nil {
		return err
	}

	go func() {
		ctx := context.WithoutCancel(ctx)
		if err := s.auditLogger.Log(ctx, AuditKeyResoruceBulkUpsert, resources); err != nil {
			s.logger.Error(ctx, "failed to record audit log", "error", err)
		}
	}()

	return nil
}

// Update updates only details and labels of a resource by ID
func (s *Service) Update(ctx context.Context, r *domain.Resource) error {
	filterBy := r.ID
	if r.ID == "" {
		filterBy = r.GlobalURN
	}

	existingResource, err := s.GetOne(ctx, filterBy)
	if err != nil {
		return err
	}

	// Details[ReservedDetailsKeyMetadata] is not allowed to be updated by users
	// value for this field should only set by the provider on FetchResources
	delete(r.Details, ReservedDetailsKeyMetadata)

	if err := mergo.Merge(r, existingResource); err != nil {
		return err
	}
	s.logger.Debug(ctx, "merged existing resource with updated resource", "resource", r.ID)

	res := &domain.Resource{
		ID:      r.ID,
		Details: r.Details,
		Labels:  r.Labels,
	}
	if err := s.repo.Update(ctx, res); err != nil {
		s.logger.Error(ctx, "failed to update resource", "resource", r.ID, "error", err)
		return err
	}
	s.logger.Info(ctx, "resource updated", "resource", r.ID)

	r.UpdatedAt = res.UpdatedAt

	go func() {
		ctx := context.WithoutCancel(ctx)
		if err := s.auditLogger.Log(ctx, AuditKeyResourceUpdate, r); err != nil {
			s.logger.Error(ctx, "failed to record audit log", "error", err)
		}
	}()

	return nil
}

func (s *Service) Get(ctx context.Context, ri *domain.ResourceIdentifier) (*domain.Resource, error) {
	var resource *domain.Resource
	if ri.ID != "" {
		if r, err := s.GetOne(ctx, ri.ID); err != nil {
			return nil, err
		} else {
			resource = r
		}
	} else {
		if resources, err := s.Find(ctx, domain.ListResourcesFilter{
			ProviderType: ri.ProviderType,
			ProviderURN:  ri.ProviderURN,
			ResourceType: ri.Type,
			ResourceURN:  ri.URN,
		}); err != nil {
			return nil, err
		} else {
			if len(resources) == 0 {
				return nil, ErrRecordNotFound
			} else {
				resource = resources[0]
			}
		}
	}
	return resource, nil
}

func (s *Service) Delete(ctx context.Context, id string) error {
	if err := s.repo.Delete(ctx, id); err != nil {
		s.logger.Error(ctx, "failed to delete resource", "resource", id, "error", err)
		return err
	}
	s.logger.Info(ctx, "resource deleted", "resource", id)

	go func() {
		ctx := context.WithoutCancel(ctx)
		if err := s.auditLogger.Log(ctx, AuditKeyResourceDelete, map[string]interface{}{"id": id}); err != nil {
			s.logger.Error(ctx, "failed to record audit log", "error", err)
		}
	}()

	return nil
}

func (s *Service) BatchDelete(ctx context.Context, ids []string) error {
	if err := s.repo.BatchDelete(ctx, ids); err != nil {
		s.logger.Error(ctx, "failed to delete resources", "resources", len(ids), "error", err)
		return err
	}
	s.logger.Info(ctx, "resources deleted", "resources", len(ids))

	go func() {
		ctx := context.WithoutCancel(ctx)
		if err := s.auditLogger.Log(ctx, AuditKeyResourceBatchDelete, map[string]interface{}{"ids": ids}); err != nil {
			s.logger.Error(ctx, "failed to record audit log", "error", err)
		}
	}()

	return nil
}

func (s *Service) GetResourcesTotalCount(ctx context.Context, filters domain.ListResourcesFilter) (int64, error) {
	return s.repo.GetResourcesTotalCount(ctx, filters)
}
