package appeal

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/go-playground/validator/v10"
	"github.com/mitchellh/mapstructure"
	"golang.org/x/sync/errgroup"

	"github.com/goto/guardian/core/comment"
	"github.com/goto/guardian/core/event"
	"github.com/goto/guardian/core/grant"
	"github.com/goto/guardian/core/policy"
	"github.com/goto/guardian/domain"
	"github.com/goto/guardian/pkg/evaluator"
	"github.com/goto/guardian/pkg/http"
	"github.com/goto/guardian/pkg/log"
	"github.com/goto/guardian/plugins/notifiers"
	"github.com/goto/guardian/utils"
)

const (
	AuditKeyBulkInsert     = "appeal.bulkInsert"
	AuditKeyUpdate         = "appeal.update"
	AuditKeyCancel         = "appeal.cancel"
	AuditKeyApprove        = "appeal.approve"
	AuditKeyReject         = "appeal.reject"
	AuditKeyRevoke         = "appeal.revoke"
	AuditKeyExtend         = "appeal.extend"
	AuditKeyAddApprover    = "appeal.addApprover"
	AuditKeyDeleteApprover = "appeal.deleteApprover"

	RevokeReasonForExtension = "Automatically revoked for grant extension"
	RevokeReasonForOverride  = "Automatically revoked for grant override"
)

var TimeNow = time.Now

//go:generate mockery --name=repository --exported --with-expecter
type repository interface {
	BulkUpsert(context.Context, []*domain.Appeal) error
	Find(context.Context, *domain.ListAppealsFilter) ([]*domain.Appeal, error)
	GetByID(ctx context.Context, id string) (*domain.Appeal, error)
	UpdateByID(context.Context, *domain.Appeal) error
	Update(context.Context, *domain.Appeal) error
	UpdateLabels(context.Context, *domain.Appeal) error
	GetAppealsTotalCount(context.Context, *domain.ListAppealsFilter) (int64, error)
	GenerateSummary(context.Context, *domain.ListAppealsFilter) (*domain.SummaryResult, error)
}

//go:generate mockery --name=iamManager --exported --with-expecter
type iamManager interface {
	domain.IAMManager
}

//go:generate mockery --name=notifier --exported --with-expecter
type notifier interface {
	notifiers.Client
}

//go:generate mockery --name=policyService --exported --with-expecter
type policyService interface {
	Find(context.Context, domain.ListPoliciesFilter) ([]*domain.Policy, error)
	GetOne(context.Context, string, uint) (*domain.Policy, error)
}

//go:generate mockery --name=approvalService --exported --with-expecter
type approvalService interface {
	AddApprover(ctx context.Context, approvalID, email string) error
	DeleteApprover(ctx context.Context, approvalID, email string) error
}

//go:generate mockery --name=providerService --exported --with-expecter
type providerService interface {
	Find(context.Context, domain.ListProvidersFilter) ([]*domain.Provider, error)
	GrantAccess(context.Context, domain.Grant) error
	RevokeAccess(context.Context, domain.Grant) error
	ValidateAppeal(context.Context, *domain.Appeal, *domain.Provider, *domain.Policy) error
	GetPermissions(context.Context, *domain.ProviderConfig, string, string) ([]interface{}, error)
	IsExclusiveRoleAssignment(context.Context, string, string) bool
	GetDependencyGrants(context.Context, domain.Grant) ([]*domain.Grant, error)
}

//go:generate mockery --name=resourceService --exported --with-expecter
type resourceService interface {
	Find(context.Context, domain.ListResourcesFilter) ([]*domain.Resource, error)
	Get(context.Context, *domain.ResourceIdentifier) (*domain.Resource, error)
}

//go:generate mockery --name=grantService --exported --with-expecter
type grantService interface {
	List(context.Context, domain.ListGrantsFilter) ([]domain.Grant, error)
	Prepare(context.Context, domain.Appeal) (*domain.Grant, error)
	Revoke(ctx context.Context, id, actor, reason string, opts ...grant.Option) (*domain.Grant, error)
	Create(ctx context.Context, grant *domain.Grant) error
}

//go:generate mockery --name=auditLogger --exported --with-expecter
type auditLogger interface {
	Log(ctx context.Context, action string, data interface{}) error
}

//go:generate mockery --name=labelingService --exported --with-expecter
type labelingService interface {
	ApplyLabels(ctx context.Context, appeal *domain.Appeal, resource *domain.Resource, policy *domain.Policy) (map[string]*domain.LabelMetadata, error)
	ValidateUserLabels(ctx context.Context, labels map[string]string, config *domain.UserLabelConfig) error
	MergeLabels(policyLabels, userLabels map[string]*domain.LabelMetadata, allowOverride bool) map[string]*domain.LabelMetadata
}

type CreateAppealOption func(*createAppealOptions)

type createAppealOptions struct {
	IsAdditionalAppeal bool
	DryRun             bool
}

func CreateWithAdditionalAppeal() CreateAppealOption {
	return func(opts *createAppealOptions) {
		opts.IsAdditionalAppeal = true
	}
}

func CreateWithDryRun() CreateAppealOption {
	return func(opts *createAppealOptions) {
		opts.DryRun = true
	}
}

type ServiceDeps struct {
	Repository      repository
	ApprovalService approvalService
	ResourceService resourceService
	ProviderService providerService
	PolicyService   policyService
	GrantService    grantService
	CommentService  *comment.Service
	EventService    *event.Service
	IAMManager      iamManager
	LabelingService labelingService

	Notifier    notifier
	Validator   *validator.Validate
	Logger      log.Logger
	AuditLogger auditLogger
}

// Service handling the business logics
type Service struct {
	repo            repository
	approvalService approvalService
	resourceService resourceService
	providerService providerService
	policyService   policyService
	grantService    grantService
	commentService  *comment.Service
	eventService    *event.Service
	iam             domain.IAMManager
	labelingService labelingService

	notifier    notifier
	validator   *validator.Validate
	logger      log.Logger
	auditLogger auditLogger

	TimeNow func() time.Time
}

// NewService returns service struct
func NewService(deps ServiceDeps) *Service {
	return &Service{
		deps.Repository,
		deps.ApprovalService,
		deps.ResourceService,
		deps.ProviderService,
		deps.PolicyService,
		deps.GrantService,
		deps.CommentService,
		deps.EventService,
		deps.IAMManager,
		deps.LabelingService,

		deps.Notifier,
		deps.Validator,
		deps.Logger,
		deps.AuditLogger,
		time.Now,
	}
}

// GetByID returns one record by id
func (s *Service) GetByID(ctx context.Context, id string) (*domain.Appeal, error) {
	if id == "" {
		return nil, ErrAppealIDEmptyParam
	}

	if !utils.IsValidUUID(id) {
		return nil, InvalidError{AppealID: id}
	}

	return s.repo.GetByID(ctx, id)
}

// Find appeals by filters
func (s *Service) Find(ctx context.Context, filters *domain.ListAppealsFilter) ([]*domain.Appeal, error) {
	return s.repo.Find(ctx, filters)
}

// Create record
func (s *Service) Create(ctx context.Context, appeals []*domain.Appeal, opts ...CreateAppealOption) error {
	createAppealOpts := &createAppealOptions{}
	for _, opt := range opts {
		opt(createAppealOpts)
	}
	isAdditionalAppealCreation := createAppealOpts.IsAdditionalAppeal

	resourceIDs := []string{}
	accountIDs := []string{}
	for _, a := range appeals {
		resourceIDs = append(resourceIDs, a.ResourceID)
		accountIDs = append(accountIDs, a.AccountID)
	}

	eg, egctx := errgroup.WithContext(ctx)
	var (
		resources      map[string]*domain.Resource
		providers      map[string]map[string]*domain.Provider
		policies       map[string]map[uint]*domain.Policy
		pendingAppeals map[string]map[string]map[string]*domain.Appeal
	)

	eg.Go(func() error {
		resourcesData, err := s.getResourcesMap(egctx, resourceIDs)
		if err != nil {
			return fmt.Errorf("error getting resource map: %w", err)
		}
		resources = resourcesData
		return nil
	})

	eg.Go(func() error {
		providersData, err := s.getProvidersMap(egctx)
		if err != nil {
			return fmt.Errorf("error getting providers map: %w", err)
		}
		providers = providersData
		return nil
	})

	eg.Go(func() error {
		policiesData, err := s.getPoliciesMap(egctx)
		if err != nil {
			return fmt.Errorf("error getting policies map: %w", err)
		}
		policies = policiesData
		return nil
	})

	eg.Go(func() error {
		pendingAppealsData, err := s.getAppealsMap(egctx, &domain.ListAppealsFilter{
			Statuses:   []string{domain.AppealStatusPending},
			AccountIDs: accountIDs,
		})
		if err != nil {
			return fmt.Errorf("listing pending appeals: %w", err)
		}
		pendingAppeals = pendingAppealsData
		return nil
	})

	if err := eg.Wait(); err != nil {
		return err
	}

	notifications := []domain.Notification{}

	for _, appeal := range appeals {
		appeal.SetDefaults()

		if !createAppealOpts.DryRun { // ignore multiple identical appeal creation check on dry-run
			if err := validateAppeal(appeal, pendingAppeals); err != nil {
				return err
			}
		}

		if err := addResource(appeal, resources); err != nil {
			return fmt.Errorf("couldn't find resource with id %q: %w", appeal.ResourceID, err)
		}
		provider, err := getProvider(appeal, providers)
		if err != nil {
			return err
		}

		var policy *domain.Policy
		if isAdditionalAppealCreation && appeal.PolicyID != "" && appeal.PolicyVersion != 0 {
			policy = policies[appeal.PolicyID][appeal.PolicyVersion]
		} else {
			policy, err = getPolicy(appeal, provider, policies)
			if err != nil {
				return err
			}
		}

		if !createAppealOpts.DryRun { // ignore grant extension eligibility check on dry-run
			activeGrant, err := s.findActiveGrant(ctx, appeal)
			if err != nil && err != ErrGrantNotFound {
				return err
			}

			if activeGrant != nil {
				if err := s.checkExtensionEligibility(appeal, provider, policy, activeGrant); err != nil {
					return err
				}
			}
		}

		if err := s.providerService.ValidateAppeal(ctx, appeal, provider, policy); err != nil {
			return fmt.Errorf("provider validation: %w", err)
		}

		strPermissions, err := s.getPermissions(ctx, provider.Config, appeal.Resource.Type, appeal.Role)

		if err != nil {
			return fmt.Errorf("getting permissions list: %w", err)
		}
		appeal.Permissions = strPermissions
		if err := validateAppealOptionsConfig(appeal, policy); err != nil {
			return err
		}

		if err := validateAppealOnBehalf(appeal, policy); err != nil {
			return err
		}

		if err := s.addCreatorDetails(ctx, appeal, policy); err != nil {
			return fmt.Errorf("getting creator details: %w", err)
		}

		if err := s.populateAppealMetadata(ctx, appeal, policy); err != nil {
			return fmt.Errorf("getting appeal metadata: %w", err)
		}

		steps, err := s.GetCustomSteps(ctx, appeal, policy)
		if err != nil {
			return fmt.Errorf("getting custom steps : %w", err)
		}
		if steps != nil {
			policy.Steps = append(policy.Steps, steps...)
		}

		appeal.Revision = 0
		if err := appeal.ApplyPolicy(policy); err != nil {
			return err
		}

		if err := s.applyLabeling(ctx, appeal, policy); err != nil {
			return fmt.Errorf("applying labels: %w", err)
		}

		if createAppealOpts.DryRun {
			if err := appeal.DryRunAdvanceApproval(policy); err != nil {
				return fmt.Errorf("initializing dry-run approvals: %w", err)
			}
		} else {
			if err := appeal.AdvanceApproval(policy); err != nil {
				return fmt.Errorf("initializing approvals: %w", err)
			}
		}
		appeal.Policy = nil

		if createAppealOpts.DryRun {
			return nil
		}

		for _, approval := range appeal.Approvals {
			// TODO: direcly check on appeal.Status==domain.AppealStatusApproved instead of manual looping through approvals
			if approval.Index == len(appeal.Approvals)-1 && (approval.Status == domain.ApprovalStatusApproved || appeal.Status == domain.AppealStatusApproved) {
				newGrant, prevGrant, err := s.prepareGrant(ctx, appeal)
				if err != nil {
					return fmt.Errorf("preparing grant: %w", err)
				}
				newGrant.Resource = appeal.Resource
				appeal.Grant = newGrant
				if prevGrant != nil {
					if _, err := s.grantService.Revoke(ctx, prevGrant.ID, domain.SystemActorName, prevGrant.RevokeReason,
						grant.SkipNotifications(),
						grant.SkipRevokeAccessInProvider(),
					); err != nil {
						return fmt.Errorf("revoking previous grant: %w", err)
					}
				}

				if err := s.GrantAccessToProvider(ctx, appeal, opts...); err != nil {
					return fmt.Errorf("granting access: %w", err)
				}

				notifications = append(notifications, domain.Notification{
					User: appeal.CreatedBy,
					Labels: map[string]string{
						"appeal_id": appeal.ID,
					},
					Message: domain.NotificationMessage{
						Type: domain.NotificationTypeAppealApproved,
						Variables: map[string]interface{}{
							"resource_name": fmt.Sprintf("%s (%s: %s)", appeal.Resource.Name, appeal.Resource.ProviderType, appeal.Resource.URN),
							"role":          appeal.Role,
							"account_id":    appeal.AccountID,
							"appeal_id":     appeal.ID,
							"requestor":     appeal.CreatedBy,
						},
					},
				})

				notifications = addOnBehalfApprovedNotification(appeal, notifications)
			}
		}
	}

	if err := s.repo.BulkUpsert(ctx, appeals); err != nil {
		return fmt.Errorf("inserting appeals into db: %w", err)
	}

	go func() {
		ctx := context.WithoutCancel(ctx)
		if err := s.auditLogger.Log(ctx, AuditKeyBulkInsert, appeals); err != nil {
			s.logger.Error(ctx, "failed to record audit log", "error", err)
		}
	}()

	for _, a := range appeals {
		if a.Status == domain.AppealStatusRejected {
			var reason string
			for _, approval := range a.Approvals {
				if approval.Status == domain.ApprovalStatusRejected {
					reason = approval.Reason
					break
				}
			}

			notifications = append(notifications, domain.Notification{
				User: a.CreatedBy,
				Labels: map[string]string{
					"appeal_id": a.ID,
				},
				Message: domain.NotificationMessage{
					Type: domain.NotificationTypeAppealRejected,
					Variables: map[string]interface{}{
						"resource_name": fmt.Sprintf("%s (%s: %s)", a.Resource.Name, a.Resource.ProviderType, a.Resource.URN),
						"role":          a.Role,
						"account_id":    a.AccountID,
						"appeal_id":     a.ID,
						"requestor":     a.CreatedBy,
						"reason":        reason,
					},
				},
			})
		}

		notifications = append(notifications, s.getApprovalNotifications(ctx, a)...)
	}

	if len(notifications) > 0 {
		go func() {
			ctx := context.WithoutCancel(ctx)
			if errs := s.notifier.Notify(ctx, notifications); errs != nil {
				for _, err1 := range errs {
					s.logger.Error(ctx, "failed to send notifications", "error", err1.Error())
				}
			}
		}()
	}

	return nil
}

func (s *Service) findActiveGrant(ctx context.Context, a *domain.Appeal) (*domain.Grant, error) {
	grants, err := s.grantService.List(ctx, domain.ListGrantsFilter{
		Statuses:    []string{string(domain.GrantStatusActive)},
		AccountIDs:  []string{a.AccountID},
		ResourceIDs: []string{a.ResourceID},
		Roles:       []string{a.Role},
		OrderBy:     []string{"updated_at:desc"},
	})

	if err != nil {
		return nil, fmt.Errorf("listing active grants: %w", err)
	}

	if len(grants) == 0 {
		return nil, ErrGrantNotFound
	}

	return &grants[0], nil
}

func addOnBehalfApprovedNotification(appeal *domain.Appeal, notifications []domain.Notification) []domain.Notification {
	if appeal.AccountType == domain.DefaultAppealAccountType && appeal.AccountID != appeal.CreatedBy {
		notifications = append(notifications, domain.Notification{
			User: appeal.AccountID,
			Labels: map[string]string{
				"appeal_id": appeal.ID,
			},
			Message: domain.NotificationMessage{
				Type: domain.NotificationTypeOnBehalfAppealApproved,
				Variables: map[string]interface{}{
					"appeal_id":     appeal.ID,
					"resource_name": fmt.Sprintf("%s (%s: %s)", appeal.Resource.Name, appeal.Resource.ProviderType, appeal.Resource.URN),
					"role":          appeal.Role,
					"account_id":    appeal.AccountID,
					"requestor":     appeal.CreatedBy,
				},
			},
		})
	}
	return notifications
}

func validateAppealOptionsConfig(appeal *domain.Appeal, policy *domain.Policy) error {
	// Validate that both ExpirationDate and Duration are not provided
	if appeal.Options != nil && appeal.Options.ExpirationDate != nil && appeal.Options.Duration != "" {
		return fmt.Errorf("cannot specify both expiration_date and duration, please provide only one")
	}

	// Validate ExpirationDate is in the future
	if appeal.Options != nil && appeal.Options.ExpirationDate != nil {
		duration := time.Until(*appeal.Options.ExpirationDate)
		if duration <= 0 {
			return fmt.Errorf("expiration date must be in the future, got: %v", *appeal.Options.ExpirationDate)
		}
		return nil
	}

	// return nil if duration options are not configured for this policy
	if policy.AppealConfig == nil || policy.AppealConfig.DurationOptions == nil {
		return nil
	}

	for _, durationOption := range policy.AppealConfig.DurationOptions {
		if appeal.Options.Duration == durationOption.Value {
			return nil
		}
	}

	return fmt.Errorf("invalid duration: %w: %q", ErrDurationNotAllowed, appeal.Options.Duration)
}

func validateAppealOnBehalf(a *domain.Appeal, policy *domain.Policy) error {
	if a.AccountType == domain.DefaultAppealAccountType {
		if policy.AppealConfig != nil && policy.AppealConfig.AllowOnBehalf {
			return nil
		}
		if a.AccountID != a.CreatedBy {
			return ErrCannotCreateAppealForOtherUser
		}
	}
	return nil
}

// Relabel reapplies labeling rules to an existing appeal based on updated policy configuration
func (s *Service) Relabel(ctx context.Context, appealID string, policyVersion *uint, dryRun bool) (*domain.Appeal, error) {
	if appealID == "" {
		return nil, ErrAppealIDEmptyParam
	}

	existingAppeal, err := s.GetByID(ctx, appealID)
	if err != nil {
		return nil, fmt.Errorf("error getting existing appeal: %w", err)
	}

	if existingAppeal.Resource == nil {
		resource, err := s.resourceService.Get(ctx, &domain.ResourceIdentifier{ID: existingAppeal.ResourceID})
		if err != nil {
			return nil, fmt.Errorf("error getting resource: %w", err)
		}
		existingAppeal.Resource = resource
	}

	var policy *domain.Policy
	policyVersionToFetch := existingAppeal.PolicyVersion

	if policyVersion != nil {
		policyVersionToFetch = *policyVersion
	}

	policy, err = s.policyService.GetOne(ctx, existingAppeal.PolicyID, policyVersionToFetch)
	if err != nil {
		return nil, fmt.Errorf("error getting policy version %d: %w", policyVersionToFetch, err)
	}

	if err := s.applyLabeling(ctx, existingAppeal, policy); err != nil {
		return nil, fmt.Errorf("error applying labels: %w", err)
	}

	if !dryRun {
		if err := s.repo.UpdateLabels(ctx, existingAppeal); err != nil {
			return nil, fmt.Errorf("error updating appeal: %w", err)
		}

		go func() {
			ctx := context.WithoutCancel(ctx)
			if err := s.auditLogger.Log(ctx, AuditKeyUpdate, map[string]interface{}{
				"appeal_id":      appealID,
				"action":         "relabel",
				"policy_version": policyVersionToFetch,
				"policy_id":      existingAppeal.PolicyID,
			}); err != nil {
				s.logger.Error(ctx, "failed to record audit log", "error", err)
			}
		}()

	}
	return existingAppeal, nil
}

// Patch record
func (s *Service) Patch(ctx context.Context, appeal *domain.Appeal) error {
	existingAppeal, err := s.GetByID(ctx, appeal.ID)
	if err != nil {
		return fmt.Errorf("error getting existing appeal: %w", err)
	}

	if existingAppeal.Status != domain.AppealStatusPending {
		return fmt.Errorf("%w: unable to edit appeal in status: %q", ErrAppealStatusInvalid, existingAppeal.Status)
	}

	isAppealUpdated, err := validatePatchReq(appeal, existingAppeal)
	if err != nil {
		return err
	}

	if !isAppealUpdated {
		return ErrNoChanges
	}

	eg, egctx := errgroup.WithContext(ctx)
	var (
		providers      map[string]map[string]*domain.Provider
		policies       map[string]map[uint]*domain.Policy
		pendingAppeals map[string]map[string]map[string]*domain.Appeal
	)

	eg.Go(func() error {
		if appeal.Resource == nil {
			resource, err := s.resourceService.Get(egctx, &domain.ResourceIdentifier{ID: appeal.ResourceID})
			if err != nil {
				return fmt.Errorf("error getting resource: %w", err)
			}
			appeal.Resource = resource
		}
		return nil
	})

	eg.Go(func() error {
		providersData, err := s.getProvidersMap(egctx)
		if err != nil {
			return fmt.Errorf("error getting providers map: %w", err)
		}
		providers = providersData
		return nil
	})

	eg.Go(func() error {
		policiesData, err := s.getPoliciesMap(egctx)
		if err != nil {
			return fmt.Errorf("error getting policies map: %w", err)
		}
		policies = policiesData
		return nil
	})

	eg.Go(func() error {
		pendingAppealsData, err := s.getAppealsMap(egctx, &domain.ListAppealsFilter{
			Statuses:   []string{domain.AppealStatusPending},
			AccountIDs: []string{appeal.AccountID},
		})
		if err != nil {
			return fmt.Errorf("error while listing pending appeals: %w", err)
		}
		pendingAppeals = pendingAppealsData
		return nil
	})

	if err := eg.Wait(); err != nil {
		return err
	}

	appeal.SetDefaults()

	if appeal.AccountID != existingAppeal.AccountID || appeal.ResourceID != existingAppeal.ResourceID || appeal.Role != existingAppeal.Role {
		if err := validateAppeal(appeal, pendingAppeals); err != nil {
			return err
		}
	}

	provider, err := getProvider(appeal, providers)
	if err != nil {
		return err
	}

	policy, err := getPolicy(appeal, provider, policies)
	if err != nil {
		return err
	}

	activeGrant, err := s.findActiveGrant(ctx, appeal)
	if err != nil && err != ErrGrantNotFound {
		return err
	}

	if activeGrant != nil {
		if err := s.checkExtensionEligibility(appeal, provider, policy, activeGrant); err != nil {
			return err
		}
	}

	if err := s.providerService.ValidateAppeal(ctx, appeal, provider, policy); err != nil {
		return fmt.Errorf("provider validation: %w", err)
	}

	strPermissions, err := s.getPermissions(ctx, provider.Config, appeal.Resource.Type, appeal.Role)
	if err != nil {
		return fmt.Errorf("getting permissions list: %w", err)
	}
	appeal.Permissions = strPermissions

	if err := validateAppealOptionsConfig(appeal, policy); err != nil {
		return err
	}

	if err := validateAppealOnBehalf(appeal, policy); err != nil {
		return err
	}

	if err := s.populateAppealMetadata(ctx, appeal, policy); err != nil {
		return fmt.Errorf("getting appeal metadata: %w", err)
	}

	steps, err := s.GetCustomSteps(ctx, appeal, policy)
	if err != nil {
		return fmt.Errorf("getting custom steps : %w", err)
	}
	if steps != nil {
		policy.Steps = append(policy.Steps, steps...)
	}

	if err := s.addCreatorDetails(ctx, appeal, policy); err != nil {
		return fmt.Errorf("getting creator details: %w", err)
	}

	// create new approval
	appeal.Revision = existingAppeal.Revision + 1
	if err := appeal.ApplyPolicy(policy); err != nil {
		return err
	}

	if err := s.applyLabeling(ctx, appeal, policy); err != nil {
		return fmt.Errorf("applying labels: %w", err)
	}

	if err := appeal.AdvanceApproval(policy); err != nil {
		return fmt.Errorf("initializing approvals: %w", err)
	}
	appeal.Policy = nil

	notifications := []domain.Notification{}
	for _, approval := range appeal.Approvals {
		if approval.Index == len(appeal.Approvals)-1 && (approval.Status == domain.ApprovalStatusApproved || appeal.Status == domain.AppealStatusApproved) {
			newGrant, revokedGrant, err := s.prepareGrant(ctx, appeal)
			if err != nil {
				return fmt.Errorf("preparing grant: %w", err)
			}
			newGrant.Resource = appeal.Resource
			appeal.Grant = newGrant
			if revokedGrant != nil {
				if _, err := s.grantService.Revoke(ctx, revokedGrant.ID, domain.SystemActorName, revokedGrant.RevokeReason,
					grant.SkipNotifications(),
					grant.SkipRevokeAccessInProvider(),
				); err != nil {
					return fmt.Errorf("revoking previous grant: %w", err)
				}
			} else {
				if err := s.GrantAccessToProvider(ctx, appeal); err != nil {
					return fmt.Errorf("granting access: %w", err)
				}
			}

			notifications = append(notifications, domain.Notification{
				User: appeal.CreatedBy,
				Labels: map[string]string{
					"appeal_id": appeal.ID,
				},
				Message: domain.NotificationMessage{
					Type: domain.NotificationTypeAppealApproved,
					Variables: map[string]interface{}{
						"resource_name": fmt.Sprintf("%s (%s: %s)", appeal.Resource.Name, appeal.Resource.ProviderType, appeal.Resource.URN),
						"role":          appeal.Role,
						"account_id":    appeal.AccountID,
						"appeal_id":     appeal.ID,
						"requestor":     appeal.CreatedBy,
					},
				},
			})

			notifications = addOnBehalfApprovedNotification(appeal, notifications)
		}
	}

	newApprovals := appeal.Approvals

	// mark previous approvals as stale
	for _, approval := range existingAppeal.Approvals {
		approval.IsStale = true

		// clear approvers so it won't get inserted to db
		// TODO: change Approvers type to Approver[] instead of string[] to keep each ID
		approval.Approvers = []string{}

		appeal.Approvals = append(appeal.Approvals, approval)
	}

	if err := s.repo.UpdateByID(ctx, appeal); err != nil {
		return fmt.Errorf("error saving appeal to db: %w", err)
	}

	diff, err := appeal.Compare(existingAppeal, appeal.CreatedBy)
	if err != nil {
		return fmt.Errorf("error comparing appeals: %w", err)
	}

	auditLog := map[string]interface{}{
		"appeal_id": appeal.ID,
		"revision":  appeal.Revision,
		"diff":      diff,
	}
	go func() {
		ctx := context.WithoutCancel(ctx)
		if err := s.auditLogger.Log(ctx, AuditKeyUpdate, auditLog); err != nil {
			s.logger.Error(ctx, "failed to record audit log", "error", err)
		}
	}()

	appeal.Approvals = newApprovals
	if appeal.Status == domain.AppealStatusApproved {
		notifications = append(notifications, domain.Notification{
			User: appeal.CreatedBy,
			Labels: map[string]string{
				"appeal_id": appeal.ID,
			},
			Message: domain.NotificationMessage{
				Type: domain.NotificationTypeAppealApproved,
				Variables: map[string]interface{}{
					"resource_name": fmt.Sprintf("%s (%s: %s)", appeal.Resource.Name, appeal.Resource.ProviderType, appeal.Resource.URN),
					"role":          appeal.Role,
					"account_id":    appeal.AccountID,
					"appeal_id":     appeal.ID,
					"requestor":     appeal.CreatedBy,
				},
			},
		})
		notifications = addOnBehalfApprovedNotification(appeal, notifications)
	} else if appeal.Status == domain.AppealStatusRejected {
		var reason string
		for _, approval := range appeal.Approvals {
			if approval.Status == domain.ApprovalStatusRejected {
				reason = approval.Reason
				break
			}
		}
		notifications = append(notifications, domain.Notification{
			User: appeal.CreatedBy,
			Labels: map[string]string{
				"appeal_id": appeal.ID,
			},
			Message: domain.NotificationMessage{
				Type: domain.NotificationTypeAppealRejected,
				Variables: map[string]interface{}{
					"resource_name": fmt.Sprintf("%s (%s: %s)", appeal.Resource.Name, appeal.Resource.ProviderType, appeal.Resource.URN),
					"role":          appeal.Role,
					"account_id":    appeal.AccountID,
					"appeal_id":     appeal.ID,
					"requestor":     appeal.CreatedBy,
					"reason":        reason,
				},
			},
		})
	} else {
		notifications = append(notifications, s.getApprovalNotifications(ctx, appeal)...)
	}

	if len(notifications) > 0 {
		go func() {
			ctx := context.WithoutCancel(ctx)
			if errs := s.notifier.Notify(ctx, notifications); errs != nil {
				for _, err1 := range errs {
					s.logger.Error(ctx, "failed to send notifications", "error", err1.Error())
				}
			}
		}()
	}

	return nil
}

func validatePatchReq(appeal, existingAppeal *domain.Appeal) (bool, error) {
	var isAppealUpdated bool

	updateField := func(newVal, existingVal string) string {
		if newVal == "" || newVal == existingVal {
			return existingVal
		}
		isAppealUpdated = true
		return newVal
	}

	appeal.AccountID = updateField(appeal.AccountID, existingAppeal.AccountID)
	appeal.AccountType = updateField(appeal.AccountType, existingAppeal.AccountType)
	appeal.Description = updateField(appeal.Description, existingAppeal.Description)
	appeal.Role = updateField(appeal.Role, existingAppeal.Role)
	appeal.ResourceID = updateField(appeal.ResourceID, existingAppeal.ResourceID)
	if appeal.ResourceID == existingAppeal.ResourceID {
		appeal.Resource = existingAppeal.Resource
	}

	if appeal.Options == nil || reflect.DeepEqual(appeal.Options, existingAppeal.Options) {
		appeal.Options = existingAppeal.Options
	} else {
		isAppealUpdated = true
	}

	if appeal.Details == nil || reflect.DeepEqual(appeal.Details, existingAppeal.Details) {
		appeal.Details = existingAppeal.Details
	} else {
		for key, value := range appeal.Details {
			if existingValue, found := existingAppeal.Details[key]; !found || !reflect.DeepEqual(existingValue, value) {
				isAppealUpdated = true
			}
		}
	}

	if appeal.Labels == nil || reflect.DeepEqual(appeal.Labels, existingAppeal.Labels) {
		appeal.Labels = existingAppeal.Labels
	} else {
		isAppealUpdated = true
	}

	appeal.CreatedBy = updateField(appeal.CreatedBy, existingAppeal.CreatedBy)
	if appeal.CreatedBy != existingAppeal.CreatedBy {
		return false, fmt.Errorf("not allowed to update creator")
	}

	appeal.Creator = existingAppeal.Creator
	appeal.Status = existingAppeal.Status

	return isAppealUpdated, nil
}

// UpdateApproval Approve an approval step
func (s *Service) UpdateApproval(ctx context.Context, approvalAction domain.ApprovalAction) (*domain.Appeal, error) {
	if err := approvalAction.Validate(); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidUpdateApprovalParameter, err)
	}

	appeal, err := s.GetByID(ctx, approvalAction.AppealID)
	if err != nil {
		if errors.Is(err, ErrAppealNotFound) {
			return nil, fmt.Errorf("%w: %q", ErrAppealNotFound, approvalAction.AppealID)
		}
		return nil, err
	}

	if err := checkIfAppealStatusStillPending(appeal.Status); err != nil {
		return nil, err
	}

	currentApproval := appeal.GetApproval(approvalAction.ApprovalName)
	if currentApproval == nil {
		return nil, fmt.Errorf("%w: %q", ErrApprovalNotFound, approvalAction.ApprovalName)
	}

	// validate previous approvals status
	for i := 0; i < currentApproval.Index; i++ {
		prevApproval := appeal.GetApprovalByIndex(i)
		if prevApproval == nil {
			return nil, fmt.Errorf("unable to find approval with index %d", i)
		}
		if err := checkPreviousApprovalStatus(prevApproval.Status, prevApproval.Name); err != nil {
			return nil, err
		}
	}

	// validate current approval status
	if err := checkApprovalStatus(currentApproval.Status); err != nil {
		return nil, err
	}
	if !currentApproval.IsExistingApprover(approvalAction.Actor) {
		return nil, ErrActionForbidden
	}

	// update approval
	currentApproval.Actor = &approvalAction.Actor
	currentApproval.Reason = approvalAction.Reason
	currentApproval.UpdatedAt = TimeNow()
	if approvalAction.Action == domain.AppealActionNameApprove {
		if appeal.Policy == nil {
			appeal.Policy, err = s.policyService.GetOne(ctx, appeal.PolicyID, appeal.PolicyVersion)
			if err != nil {
				return nil, err
			}
		}

		isSelfApprovalNotAllowed := false
		policyStep := appeal.Policy.GetStepByName(currentApproval.Name)
		if policyStep == nil {
			isStepValid := false
			if appeal.Policy.HasCustomSteps() {
				for _, ap := range appeal.Approvals {
					if ap.Name == currentApproval.Name {
						isStepValid = true
						isSelfApprovalNotAllowed = ap.DontAllowSelfApproval
					}
				}
			}
			if !isStepValid {
				return nil, fmt.Errorf("%w: %q for appeal %q", ErrNoPolicyStepFound, approvalAction.ApprovalName, appeal.ID)
			}
		} else {
			isSelfApprovalNotAllowed = policyStep.DontAllowSelfApproval
		}

		// check if user is self approving the appeal
		if isSelfApprovalNotAllowed {
			if approvalAction.Actor == appeal.CreatedBy {
				return nil, ErrSelfApprovalNotAllowed
			}
		}

		currentApproval.Approve()

		// mark next approval as pending
		nextApproval := appeal.GetApprovalByIndex(currentApproval.Index + 1)
		if nextApproval != nil {
			nextApproval.Status = domain.ApprovalStatusPending
		}

		if err := appeal.AdvanceApproval(appeal.Policy); err != nil {
			return nil, err
		}
	} else if approvalAction.Action == domain.AppealActionNameReject {
		currentApproval.Reject()
		appeal.Reject()

		// mark the rest of approvals as skipped
		i := currentApproval.Index
		for {
			nextApproval := appeal.GetApprovalByIndex(i + 1)
			if nextApproval == nil {
				break
			}
			nextApproval.Skip()
			nextApproval.UpdatedAt = TimeNow()
			i++
		}
	} else {
		return nil, ErrActionInvalidValue
	}

	// evaluate final appeal status
	if appeal.Status == domain.AppealStatusApproved {
		newGrant, prevGrant, err := s.prepareGrant(ctx, appeal)
		if err != nil {
			return nil, fmt.Errorf("preparing grant: %w", err)
		}
		newGrant.Resource = appeal.Resource
		appeal.Grant = newGrant
		if prevGrant != nil {
			if _, err := s.grantService.Revoke(ctx, prevGrant.ID, domain.SystemActorName, prevGrant.RevokeReason,
				grant.SkipNotifications(),
				grant.SkipRevokeAccessInProvider(),
			); err != nil {
				return nil, fmt.Errorf("revoking previous grant: %w", err)
			}
		}

		if err := s.GrantAccessToProvider(ctx, appeal); err != nil {
			return nil, fmt.Errorf("granting access: %w", err)
		}
	}

	if err := s.Update(ctx, appeal); err != nil {
		if !errors.Is(err, domain.ErrDuplicateActiveGrant) {
			if err := s.providerService.RevokeAccess(ctx, *appeal.Grant); err != nil {
				return nil, fmt.Errorf("revoking access: %w", err)
			}
		}
		return nil, fmt.Errorf("updating appeal: %w", err)
	}

	notifications := []domain.Notification{}
	if appeal.Status == domain.AppealStatusApproved {
		notifications = append(notifications, domain.Notification{
			User: appeal.CreatedBy,
			Labels: map[string]string{
				"appeal_id": appeal.ID,
			},
			Message: domain.NotificationMessage{
				Type: domain.NotificationTypeAppealApproved,
				Variables: map[string]interface{}{
					"resource_name": fmt.Sprintf("%s (%s: %s)", appeal.Resource.Name, appeal.Resource.ProviderType, appeal.Resource.URN),
					"role":          appeal.Role,
					"account_id":    appeal.AccountID,
					"appeal_id":     appeal.ID,
					"requestor":     appeal.CreatedBy,
				},
			},
		})
		notifications = addOnBehalfApprovedNotification(appeal, notifications)
	} else if appeal.Status == domain.AppealStatusRejected {
		notifications = append(notifications, domain.Notification{
			User: appeal.CreatedBy,
			Labels: map[string]string{
				"appeal_id": appeal.ID,
			},
			Message: domain.NotificationMessage{
				Type: domain.NotificationTypeAppealRejected,
				Variables: map[string]interface{}{
					"resource_name": fmt.Sprintf("%s (%s: %s)", appeal.Resource.Name, appeal.Resource.ProviderType, appeal.Resource.URN),
					"role":          appeal.Role,
					"account_id":    appeal.AccountID,
					"appeal_id":     appeal.ID,
					"requestor":     appeal.CreatedBy,
				},
			},
		})
	} else {
		notifications = append(notifications, s.getApprovalNotifications(ctx, appeal)...)
	}
	if len(notifications) > 0 {
		go func() {
			ctx := context.WithoutCancel(ctx)
			if errs := s.notifier.Notify(ctx, notifications); errs != nil {
				for _, err1 := range errs {
					s.logger.Error(ctx, "failed to send notifications", "error", err1.Error())
				}
			}
		}()
	}

	var auditKey string
	if approvalAction.Action == string(domain.ApprovalActionReject) {
		auditKey = AuditKeyReject
	} else if approvalAction.Action == string(domain.ApprovalActionApprove) {
		auditKey = AuditKeyApprove
	}
	if auditKey != "" {
		go func() {
			ctx := context.WithoutCancel(ctx)
			if err := s.auditLogger.Log(ctx, auditKey, approvalAction); err != nil {
				s.logger.Error(ctx, "failed to record audit log", "error", err)
			}
		}()
	}

	return appeal, nil
}

func (s *Service) Update(ctx context.Context, appeal *domain.Appeal) error {
	return s.repo.Update(ctx, appeal)
}

func (s *Service) Cancel(ctx context.Context, id string) (*domain.Appeal, error) {
	if id == "" {
		return nil, ErrAppealIDEmptyParam
	}

	if !utils.IsValidUUID(id) {
		return nil, InvalidError{AppealID: id}
	}

	appeal, err := s.GetByID(ctx, id)
	if err != nil {
		return nil, err
	}

	// TODO: check only appeal creator who is allowed to cancel the appeal

	if err := checkIfAppealStatusStillPending(appeal.Status); err != nil {
		return nil, err
	}

	appeal.Cancel()
	if err := s.repo.Update(ctx, appeal); err != nil {
		return nil, err
	}

	go func() {
		ctx := context.WithoutCancel(ctx)
		if err := s.auditLogger.Log(ctx, AuditKeyCancel, map[string]interface{}{
			"appeal_id": id,
		}); err != nil {
			s.logger.Error(ctx, "failed to record audit log", "error", err)
		}
	}()

	return appeal, nil
}

func (s *Service) AddApprover(ctx context.Context, appealID, approvalID, email string) (*domain.Appeal, error) {
	if err := s.validator.Var(email, "email"); err != nil {
		return nil, fmt.Errorf("%w: %s", ErrApproverEmail, err)
	}

	appeal, approval, err := s.getApproval(ctx, appealID, approvalID)
	if err != nil {
		return nil, err
	}
	if appeal.Status != domain.AppealStatusPending {
		return nil, fmt.Errorf("%w: can't add new approver to appeal with %q status", ErrUnableToAddApprover, appeal.Status)
	}
	if approval.IsStale {
		return nil, fmt.Errorf("%w: can't add new approver to a stale approval", ErrUnableToAddApprover)
	}
	if approval.IsExistingApprover(email) {
		return nil, fmt.Errorf("%w: approver %q already exists", ErrUnableToAddApprover, email)
	}

	switch approval.Status {
	case domain.ApprovalStatusPending:
		break
	case domain.ApprovalStatusBlocked:
		// check if approval type is auto
		// this approach is the quickest way to assume that approval is auto, otherwise need to fetch the policy details and lookup the approval type which takes more time
		if approval.Approvers == nil || len(approval.Approvers) == 0 {
			// approval is automatic (strategy: auto) that is still on blocked
			return nil, fmt.Errorf("%w: can't modify approvers for approval with strategy auto", ErrUnableToAddApprover)
		}
	default:
		return nil, fmt.Errorf("%w: can't add approver to approval with %q status", ErrUnableToAddApprover, approval.Status)
	}

	if err := s.approvalService.AddApprover(ctx, approval.ID, email); err != nil {
		return nil, fmt.Errorf("adding new approver: %w", err)
	}
	approval.Approvers = append(approval.Approvers, email)

	auditData, err := utils.StructToMap(approval)
	if err != nil {
		return nil, fmt.Errorf("converting approval to map: %w", err)
	}
	auditData["affected_approver"] = email
	go func() {
		ctx := context.WithoutCancel(ctx)
		if err := s.auditLogger.Log(ctx, AuditKeyAddApprover, auditData); err != nil {
			s.logger.Error(ctx, "failed to record audit log", "error", err)
		}
	}()

	duration := domain.PermanentDurationLabel
	if !appeal.IsDurationEmpty() {
		duration, err = utils.GetReadableDuration(appeal.Options.Duration)
		if err != nil {
			s.logger.Error(ctx, "failed to get readable duration", "error", err, "appeal_id", appeal.ID)
		}
	}

	go func() {
		ctx := context.WithoutCancel(ctx)
		if errs := s.notifier.Notify(ctx, []domain.Notification{
			{
				User: email,
				Labels: map[string]string{
					"appeal_id": appeal.ID,
				},
				Message: domain.NotificationMessage{
					Type: domain.NotificationTypeApproverNotification,
					Variables: map[string]interface{}{
						"resource_name": fmt.Sprintf("%s (%s: %s)", appeal.Resource.Name, appeal.Resource.ProviderType, appeal.Resource.URN),
						"role":          appeal.Role,
						"requestor":     appeal.CreatedBy,
						"appeal_id":     appeal.ID,
						"account_id":    appeal.AccountID,
						"account_type":  appeal.AccountType,
						"provider_type": appeal.Resource.ProviderType,
						"resource_type": appeal.Resource.Type,
						"created_at":    appeal.CreatedAt,
						"approval_step": approval.Name,
						"actor":         email,
						"details":       appeal.Details,
						"duration":      duration,
						"creator":       appeal.Creator,
					},
				},
			},
		}); errs != nil {
			for _, err1 := range errs {
				s.logger.Error(ctx, "failed to send notifications", "error", err1.Error())
			}
		}
	}()

	return appeal, nil
}

func (s *Service) DeleteApprover(ctx context.Context, appealID, approvalID, email string) (*domain.Appeal, error) {
	if err := s.validator.Var(email, "email"); err != nil {
		return nil, fmt.Errorf("%w: %s", ErrApproverEmail, err)
	}

	appeal, approval, err := s.getApproval(ctx, appealID, approvalID)
	if err != nil {
		return nil, err
	}
	if appeal.Status != domain.AppealStatusPending {
		return nil, fmt.Errorf("%w: can't delete approver to appeal with %q status", ErrUnableToDeleteApprover, appeal.Status)
	}
	if approval.IsStale {
		return nil, fmt.Errorf("%w: can't delete approver in a stale approval", ErrUnableToDeleteApprover)
	}

	switch approval.Status {
	case domain.ApprovalStatusPending:
		break
	case domain.ApprovalStatusBlocked:
		// check if approval type is auto
		// this approach is the quickest way to assume that approval is auto, otherwise need to fetch the policy details and lookup the approval type which takes more time
		if approval.Approvers == nil || len(approval.Approvers) == 0 {
			// approval is automatic (strategy: auto) that is still on blocked
			return nil, fmt.Errorf("%w: can't modify approvers for approval with strategy auto", ErrUnableToDeleteApprover)
		}
	default:
		return nil, fmt.Errorf("%w: can't delete approver to approval with %q status", ErrUnableToDeleteApprover, approval.Status)
	}

	if len(approval.Approvers) == 1 {
		return nil, fmt.Errorf("%w: can't delete if there's only one approver", ErrUnableToDeleteApprover)
	}

	if err := s.approvalService.DeleteApprover(ctx, approvalID, email); err != nil {
		return nil, err
	}

	var newApprovers []string
	for _, a := range approval.Approvers {
		if a != email {
			newApprovers = append(newApprovers, a)
		}
	}
	approval.Approvers = newApprovers

	auditData, err := utils.StructToMap(approval)
	if err != nil {
		return nil, fmt.Errorf("converting approval to map: %w", err)
	}
	auditData["affected_approver"] = email
	go func() {
		ctx := context.WithoutCancel(ctx)
		if err := s.auditLogger.Log(ctx, AuditKeyDeleteApprover, auditData); err != nil {
			s.logger.Error(ctx, "failed to record audit log", "error", err)
		}
	}()

	return appeal, nil
}

func (s *Service) getApproval(ctx context.Context, appealID, approvalID string) (*domain.Appeal, *domain.Approval, error) {
	if appealID == "" {
		return nil, nil, ErrAppealIDEmptyParam
	}
	if approvalID == "" {
		return nil, nil, ErrApprovalIDEmptyParam
	}

	appeal, err := s.repo.GetByID(ctx, appealID)
	if err != nil {
		return nil, nil, fmt.Errorf("getting appeal details: %w", err)
	}

	approval := appeal.GetApproval(approvalID)
	if approval == nil {
		return nil, nil, ErrApprovalNotFound
	}

	return appeal, approval, nil
}

// getAppealsMap returns map[account_id]map[resource_id]map[role]*domain.Appeal, error
func (s *Service) getAppealsMap(ctx context.Context, filters *domain.ListAppealsFilter) (map[string]map[string]map[string]*domain.Appeal, error) {
	appeals, err := s.repo.Find(ctx, filters)
	if err != nil {
		return nil, err
	}

	appealsMap := map[string]map[string]map[string]*domain.Appeal{}
	for _, a := range appeals {
		accountID := strings.ToLower(a.AccountID)
		if appealsMap[accountID] == nil {
			appealsMap[accountID] = map[string]map[string]*domain.Appeal{}
		}
		if appealsMap[accountID][a.ResourceID] == nil {
			appealsMap[accountID][a.ResourceID] = map[string]*domain.Appeal{}
		}
		appealsMap[accountID][a.ResourceID][a.Role] = a
	}

	return appealsMap, nil
}

func (s *Service) getResourcesMap(ctx context.Context, ids []string) (map[string]*domain.Resource, error) {
	filters := domain.ListResourcesFilter{IDs: ids}
	resources, err := s.resourceService.Find(ctx, filters)
	if err != nil {
		return nil, err
	}

	result := map[string]*domain.Resource{}
	for _, r := range resources {
		result[r.ID] = r
	}

	return result, nil
}

func (s *Service) getProvidersMap(ctx context.Context) (map[string]map[string]*domain.Provider, error) {
	providers, err := s.providerService.Find(ctx, domain.ListProvidersFilter{})
	if err != nil {
		return nil, err
	}

	providersMap := map[string]map[string]*domain.Provider{}
	for _, p := range providers {
		providerType := p.Type
		providerURN := p.URN
		if providersMap[providerType] == nil {
			providersMap[providerType] = map[string]*domain.Provider{}
		}
		if providersMap[providerType][providerURN] == nil {
			providersMap[providerType][providerURN] = p
		}
	}

	return providersMap, nil
}

func (s *Service) getPoliciesMap(ctx context.Context) (map[string]map[uint]*domain.Policy, error) {
	policies, err := s.policyService.Find(ctx, domain.ListPoliciesFilter{})
	if err != nil {
		return nil, err
	}

	policiesMap := map[string]map[uint]*domain.Policy{}
	for _, p := range policies {
		id := p.ID
		if policiesMap[id] == nil {
			policiesMap[id] = map[uint]*domain.Policy{}
		}
		policiesMap[id][p.Version] = p
		// set policiesMap[id][0] to latest policy version
		if policiesMap[id][0] == nil || p.Version > policiesMap[id][0].Version {
			policiesMap[id][0] = p
		}
	}

	return policiesMap, nil
}

func (s *Service) getApprovalNotifications(ctx context.Context, appeal *domain.Appeal) []domain.Notification {
	notifications := []domain.Notification{}
	approval := appeal.GetNextPendingApproval()

	duration := domain.PermanentDurationLabel
	var err error
	if !appeal.IsDurationEmpty() {
		duration, err = utils.GetReadableDuration(appeal.Options.Duration)
		if err != nil {
			s.logger.Error(ctx, "failed to get readable duration", "error", err, "appeal_id", appeal.ID)
		}
	}

	if approval != nil {
		for _, approver := range approval.Approvers {
			notifications = append(notifications, domain.Notification{
				User: approver,
				Labels: map[string]string{
					"appeal_id": appeal.ID,
				},
				Message: domain.NotificationMessage{
					Type: domain.NotificationTypeApproverNotification,
					Variables: map[string]interface{}{
						"resource_name": fmt.Sprintf("%s (%s: %s)", appeal.Resource.Name, appeal.Resource.ProviderType, appeal.Resource.URN),
						"role":          appeal.Role,
						"requestor":     appeal.CreatedBy,
						"appeal_id":     appeal.ID,
						"account_id":    appeal.AccountID,
						"account_type":  appeal.AccountType,
						"provider_type": appeal.Resource.ProviderType,
						"resource_type": appeal.Resource.Type,
						"created_at":    appeal.CreatedAt,
						"approval_step": approval.Name,
						"actor":         approver,
						"details":       appeal.Details,
						"duration":      duration,
						"creator":       appeal.Creator,
					},
				},
			})
		}
	}
	return notifications
}

func checkIfAppealStatusStillPending(status string) error {
	switch status {
	case domain.AppealStatusPending:
		return nil
	case
		domain.AppealStatusCanceled,
		domain.AppealStatusApproved,
		domain.AppealStatusRejected:
		return fmt.Errorf("%w: %q", ErrAppealNotEligibleForApproval, status)
	default:
		return fmt.Errorf("%w: %q", ErrAppealStatusUnrecognized, status)
	}
}

func checkPreviousApprovalStatus(status, name string) error {
	switch status {
	case
		domain.ApprovalStatusApproved,
		domain.ApprovalStatusSkipped:
		return nil
	case
		domain.ApprovalStatusBlocked,
		domain.ApprovalStatusPending,
		domain.ApprovalStatusRejected:
		return fmt.Errorf("%w: found previous approval %q with status %q", ErrApprovalNotEligibleForAction, name, status)
	default:
		return fmt.Errorf("%w: found previous approval %q with unrecognized status %q", ErrApprovalStatusUnrecognized, name, status)
	}
}

func checkApprovalStatus(status string) error {
	switch status {
	case domain.ApprovalStatusPending:
		return nil
	case
		domain.ApprovalStatusBlocked,
		domain.ApprovalStatusApproved,
		domain.ApprovalStatusRejected,
		domain.ApprovalStatusSkipped:
		return fmt.Errorf("%w: approval status %q is not actionable", ErrApprovalNotEligibleForAction, status)
	default:
		return fmt.Errorf("%w: %q", ErrApprovalStatusUnrecognized, status)
	}
}

func (s *Service) handleAppealRequirements(ctx context.Context, a *domain.Appeal, p *domain.Policy) error {
	if p.Requirements != nil && len(p.Requirements) > 0 {
		for reqIndex, r := range p.Requirements {
			isAppealMatchesRequirement, err := r.On.IsMatch(a)
			if err != nil {
				return fmt.Errorf("evaluating requirements[%v]: %v", reqIndex, err)
			}
			if !isAppealMatchesRequirement {
				continue
			}

			// Track created additional appeals for post hooks
			createdAppeals := make([]*domain.Appeal, 0, len(r.Appeals))
			var mu sync.Mutex

			g, ctx := errgroup.WithContext(ctx)
			for _, aa := range r.Appeals {
				aa := aa // https://golang.org/doc/faq#closures_and_goroutines
				g.Go(func() error {
					// TODO: populate resource data from policyService
					resource, err := s.resourceService.Get(ctx, aa.Resource)
					if err != nil {
						return fmt.Errorf("retrieving resource: %v", err)
					}

					additionalAppeal := &domain.Appeal{
						AccountID:   a.AccountID,
						AccountType: a.AccountType,
						CreatedBy:   a.CreatedBy,
						Role:        aa.Role,
						ResourceID:  resource.ID,
					}
					if aa.Options != nil {
						additionalAppeal.Options = aa.Options
					}
					if aa.Policy != nil {
						additionalAppeal.PolicyID = aa.Policy.ID
						additionalAppeal.PolicyVersion = uint(aa.Policy.Version)
					}

					if err := s.Create(ctx, []*domain.Appeal{additionalAppeal}, CreateWithAdditionalAppeal()); err != nil {
						if errors.Is(err, ErrAppealDuplicate) {
							s.logger.Warn(ctx, "creating additional appeals, duplicate appeal error log", "error", err)
							// Still track the appeal even if duplicate
							mu.Lock()
							createdAppeals = append(createdAppeals, additionalAppeal)
							mu.Unlock()
							return nil
						}
						return fmt.Errorf("creating additional appeals: %w", err)
					}

					// Track successfully created appeal
					mu.Lock()
					createdAppeals = append(createdAppeals, additionalAppeal)
					mu.Unlock()

					return nil
				})
			}

			// Wait for all additional appeals to be created
			if err := g.Wait(); err != nil {
				return err
			}

			// Execute post hooks after appeals are created
			if r.PostHooks != nil && len(r.PostHooks) > 0 {
				if err := s.executePostAppealHooks(ctx, r.PostHooks, a, createdAppeals, r, p); err != nil {
					return fmt.Errorf("executing post hooks for requirement[%d]: %w", reqIndex, err)
				}
			}
		}
	}
	return nil
}

func (s *Service) GrantAccessToProvider(ctx context.Context, a *domain.Appeal, opts ...CreateAppealOption) error {
	createAppealOpts := &createAppealOptions{}
	for _, opt := range opts {
		opt(createAppealOpts)
	}

	if createAppealOpts.DryRun {
		return nil
	}

	policy := a.Policy
	if policy == nil {
		p, err := s.policyService.GetOne(ctx, a.PolicyID, a.PolicyVersion)
		if err != nil {
			return fmt.Errorf("retrieving policy: %w", err)
		}
		policy = p
	}

	isAdditionalAppealCreation := createAppealOpts.IsAdditionalAppeal
	if !isAdditionalAppealCreation {
		if err := s.handleAppealRequirements(ctx, a, policy); err != nil {
			return fmt.Errorf("handling appeal requirements: %w", err)
		}
	}

	appealCopy := *a
	appealCopy.Grant = nil
	grantWithAppeal := *a.Grant
	grantWithAppeal.Appeal = &appealCopy
	// grant access dependencies (if any)
	dependencyGrants, err := s.providerService.GetDependencyGrants(ctx, grantWithAppeal)
	if err != nil {
		return fmt.Errorf("getting grant dependencies: %w", err)
	}
	for _, dg := range dependencyGrants {
		// Find any existing active grant for the same account/resource/permissions
		// regardless of group attributes to handle grant updates
		activeDepGrants, err := s.grantService.List(ctx, domain.ListGrantsFilter{
			Statuses:     []string{string(domain.GrantStatusActive)},
			AccountIDs:   []string{dg.AccountID},
			AccountTypes: []string{dg.AccountType},
			ResourceIDs:  []string{dg.Resource.ID},
			Permissions:  dg.Permissions,
			Size:         1,
		})
		if err != nil {
			return fmt.Errorf("failed to get existing active grant dependency: %w", err)
		}

		if len(activeDepGrants) > 0 {
			existingGrant := &activeDepGrants[0]
			// Check if the existing grant has the exact same attributes (including group)
			if existingGrant.GroupID == dg.GroupID && existingGrant.GroupType == dg.GroupType {
				// Same grant already exists, skip creating a new one
				continue
			}
			// Different group attributes detected, revoke the old grant and create new one
			// Skip revoke in provider since the access will be re-granted with new attributes
			if _, err := s.grantService.Revoke(ctx, existingGrant.ID, domain.SystemActorName, "Replaced with updated group attributes",
				grant.SkipNotifications(),
				grant.SkipRevokeAccessInProvider(),
			); err != nil {
				return fmt.Errorf("failed to revoke previous dependency grant: %w", err)
			}
		}

		dg.Status = domain.GrantStatusActive
		dg.Appeal = &appealCopy
		if err := s.providerService.GrantAccess(ctx, *dg); err != nil {
			return fmt.Errorf("failed to grant an access dependency: %w", err)
		}
		dg.Appeal = nil

		dg.Owner = a.CreatedBy
		if err := s.grantService.Create(ctx, dg); err != nil {
			return fmt.Errorf("failed to store grant of access dependency: %w", err)
		}
	}

	// grant main access
	if err := s.providerService.GrantAccess(ctx, grantWithAppeal); err != nil {
		return fmt.Errorf("granting access: %w", err)
	}

	grantWithAppeal.Appeal = nil
	return nil
}

func (s *Service) checkExtensionEligibility(a *domain.Appeal, p *domain.Provider, policy *domain.Policy, activeGrant *domain.Grant) error {
	allowActiveAccessExtensionIn := ""

	// Default to use provider config if policy config is not set
	if p.Config.Appeal != nil {
		allowActiveAccessExtensionIn = p.Config.Appeal.AllowActiveAccessExtensionIn
	}

	// Use policy config if set
	if policy != nil &&
		policy.AppealConfig != nil &&
		policy.AppealConfig.AllowActiveAccessExtensionIn != "" {
		allowActiveAccessExtensionIn = policy.AppealConfig.AllowActiveAccessExtensionIn
	}

	if allowActiveAccessExtensionIn == "" {
		return ErrAppealFoundActiveGrant
	}

	extensionDurationRule, err := time.ParseDuration(allowActiveAccessExtensionIn)
	if err != nil {
		return fmt.Errorf("%w: %q: %v", ErrAppealInvalidExtensionDuration, allowActiveAccessExtensionIn, err)
	}

	if !activeGrant.IsEligibleForExtension(extensionDurationRule) {
		return fmt.Errorf("%w: extension is allowed %q before grant expiration", ErrGrantNotEligibleForExtension, allowActiveAccessExtensionIn)
	}
	return nil
}

func getPolicy(a *domain.Appeal, p *domain.Provider, policiesMap map[string]map[uint]*domain.Policy) (*domain.Policy, error) {
	var policyConfig domain.PolicyConfig
	var resourceConfig *domain.ResourceConfig
	for _, rc := range p.Config.Resources {
		if rc.Type == a.Resource.Type {
			resourceConfig = rc
			break
		}
	}
	if resourceConfig == nil {
		return nil, fmt.Errorf("%w: couldn't find %q resource type in the provider config", ErrInvalidResourceType, a.Resource.Type)
	}
	policyConfig = *resourceConfig.Policy

	appealMap, err := a.ToMap()
	if err != nil {
		return nil, fmt.Errorf("parsing appeal struct to map: %w", err)
	}

	var dynamicPolicyConfigData string
	for _, pc := range p.Config.Policies {
		if pc.When != "" {
			v, err := evaluator.Expression(pc.When).EvaluateWithVars(map[string]interface{}{
				"appeal": appealMap,
			})
			if err != nil {
				return nil, err
			}

			isFalsy := reflect.ValueOf(v).IsZero()
			if isFalsy {
				continue
			}

			dynamicPolicyConfigData = pc.Policy
			break
		}
	}

	if dynamicPolicyConfigData != "" {
		var dynamicPolicyConfig domain.PolicyConfig
		policyData := strings.Split(dynamicPolicyConfigData, "@")
		dynamicPolicyConfig.ID = policyData[0]
		if len(policyData) > 1 {
			var version int
			if policyData[1] == "latest" {
				version = 0
			} else {
				version, err = strconv.Atoi(policyData[1])
			}
			if err != nil {
				return nil, fmt.Errorf("invalid policy version: %w", err)
			}
			dynamicPolicyConfig.Version = version
		}
		policyConfig = dynamicPolicyConfig
	}

	policy, ok := policiesMap[policyConfig.ID][uint(policyConfig.Version)]
	if !ok {
		return nil, fmt.Errorf("couldn't find details for policy %q: %w", fmt.Sprintf("%s@%v", policyConfig.ID, policyConfig.Version), ErrPolicyNotFound)
	}
	return policy, nil
}

func (s *Service) GetCustomSteps(ctx context.Context, a *domain.Appeal, p *domain.Policy) ([]*domain.Step, error) {
	if !p.HasCustomSteps() {
		return nil, nil
	}
	switch p.CustomSteps.Type {
	case "http":
		var cfg policy.AppealMetadataSourceConfigHTTP
		customStepsConfig := p.CustomSteps
		if err := mapstructure.Decode(customStepsConfig.Config, &cfg); err != nil {
			return nil, fmt.Errorf("error decoding metadata config: %w", err)
		}

		if cfg.URL == "" {
			return nil, fmt.Errorf("URL cannot be empty for http type")
		}
		var err error
		cfg.URL, err = evaluateExpressionWithAppeal(a, cfg.URL)
		if err != nil {
			return nil, fmt.Errorf("error while evaluating url %w", err)
		}

		cfg.Body, err = evaluateExpressionWithAppeal(a, cfg.Body)
		if err != nil {
			return nil, fmt.Errorf("error while evaluating body %w", err)
		}
		headers := make(map[string]string)
		for key, value := range cfg.Headers {
			if headers[key], err = evaluateExpressionWithAppeal(a, value); err != nil {
				return nil, fmt.Errorf("error while evaluating headers %w", err)
			}
		}
		cfg.Headers = headers
		clientCreator := &http.HttpClientCreatorStruct{}
		metadataCl, err := http.NewHTTPClient(&cfg.HTTPClientConfig, clientCreator, "AppealCustomSteps")
		if err != nil {
			return nil, fmt.Errorf(" error in http request %w", err)
		}

		res, err := metadataCl.MakeRequest(ctx)
		if err != nil {
			if cfg.AllowFailed {
				return nil, nil
			}
			return nil, fmt.Errorf("error fetching resource: %w", err)
		}
		defer res.Body.Close()

		body, err := io.ReadAll(res.Body)
		if err != nil {
			return nil, fmt.Errorf("error reading response body: %w", err)
		}

		if res.StatusCode < 200 || res.StatusCode > 300 {
			if cfg.AllowFailed {
				return nil, nil
			}
			bodyAsErr := strings.ReplaceAll(strings.ReplaceAll(strings.TrimSpace(string(body)), "\n", ""), `\\`, "")
			return nil, fmt.Errorf("unexpected status code '%s'. body: '%s'", fmt.Sprint(res.StatusCode), bodyAsErr)
		}

		customStepResponse := &domain.CustomStepsResponse{}
		s.logger.Info(ctx, "custom policy steps request and response ", "request", cfg.URL, "customStepResponse", string(body))
		err = json.Unmarshal(body, &customStepResponse)
		if err != nil {
			return nil, fmt.Errorf("error unmarshaling response body: %w", err)
		}

		return customStepResponse.ApprovalSteps, nil
	default:
		return nil, fmt.Errorf("invalid custom steps source type: %q", p.CustomSteps.Type)
	}
}

func (s *Service) populateAppealMetadata(ctx context.Context, a *domain.Appeal, p *domain.Policy) error {
	if !p.HasAppealMetadataSources() {
		return nil
	}

	eg, egctx := errgroup.WithContext(ctx)
	var mu sync.Mutex
	appealMetadata := map[string]interface{}{}
	for key, metadata := range p.AppealConfig.MetadataSources {
		key, metadata := key, metadata
		eg.Go(func() error {
			switch metadata.Type {
			case "http":
				var cfg policy.AppealMetadataSourceConfigHTTP
				if err := mapstructure.Decode(metadata.Config, &cfg); err != nil {
					return fmt.Errorf("error decoding metadata config: %w", err)
				}

				if cfg.URL == "" {
					return fmt.Errorf("URL cannot be empty for http type")
				}

				var err error
				cfg.URL, err = evaluateExpressionWithAppeal(a, cfg.URL)
				if err != nil {
					return err
				}

				cfg.Body, err = evaluateExpressionWithAppeal(a, cfg.Body)
				if err != nil {
					return err
				}

				clientCreator := &http.HttpClientCreatorStruct{}
				metadataCl, err := http.NewHTTPClient(&cfg.HTTPClientConfig, clientCreator, "AppealMetadata")
				if err != nil {
					return fmt.Errorf("key: %s, %w", key, err)
				}

				res, err := metadataCl.MakeRequest(egctx)
				if err != nil {
					if cfg.AllowFailed {
						return nil
					}
					return fmt.Errorf("error fetching resource: %w", err)
				}
				defer res.Body.Close()

				body, err := io.ReadAll(res.Body)
				if err != nil {
					return fmt.Errorf("error reading response body: %w", err)
				}

				if res.StatusCode < 200 || res.StatusCode > 300 {
					if cfg.AllowFailed {
						return nil
					}
					bodyAsErr := strings.ReplaceAll(strings.ReplaceAll(strings.TrimSpace(string(body)), "\n", ""), `\\`, "")
					return fmt.Errorf("unexpected status code '%s'. body: '%s'", fmt.Sprint(res.StatusCode), bodyAsErr)
				}

				var jsonBody interface{}
				err = json.Unmarshal(body, &jsonBody)
				if err != nil {
					return fmt.Errorf("error unmarshaling response body: %w", err)
				}

				responseMap := map[string]interface{}{
					"status":      res.Status,
					"status_code": res.StatusCode,
					"headers":     res.Header,
					"body":        jsonBody,
				}
				params := map[string]interface{}{
					"response": responseMap,
					"appeal":   a,
				}

				value, err := metadata.EvaluateValue(params)
				if err != nil {
					return fmt.Errorf("error parsing value: %w", err)
				}
				mu.Lock()
				appealMetadata[key] = value
				mu.Unlock()
			case "static":
				params := map[string]interface{}{"appeal": a}
				value, err := metadata.EvaluateValue(params)
				if err != nil {
					return fmt.Errorf("error parsing value: %w", err)
				}
				mu.Lock()
				appealMetadata[key] = value
				mu.Unlock()
			default:
				return fmt.Errorf("invalid metadata source type")
			}

			return nil
		})
	}

	if err := eg.Wait(); err != nil {
		return err
	}

	if a.Details == nil {
		a.Details = map[string]interface{}{}
	}
	a.Details[domain.ReservedDetailsKeyPolicyMetadata] = appealMetadata

	return nil
}

func (s *Service) applyLabeling(ctx context.Context, a *domain.Appeal, p *domain.Policy) error {
	if !p.HasLabelingConfig() {
		return nil
	}

	if s.labelingService == nil {
		return fmt.Errorf("labeling service is required but not configured")
	}

	// Extract user-provided labels from appeal.UserLabels
	userLabels := a.UserLabels
	if userLabels == nil {
		userLabels = make(map[string]string)
	}

	// Validate user labels against policy configuration
	if p.AllowsUserLabels() && len(userLabels) > 0 {
		if err := s.labelingService.ValidateUserLabels(ctx, userLabels, p.AppealConfig.UserLabelConfig); err != nil {
			return fmt.Errorf("validating user labels: %w", err)
		}
	}

	// Apply policy-based labels
	policyLabels, err := s.labelingService.ApplyLabels(ctx, a, a.Resource, p)
	if err != nil {
		return fmt.Errorf("applying policy labels: %w", err)
	}

	// Convert user labels to LabelMetadata format
	userLabelsMetadata := make(map[string]*domain.LabelMetadata)
	for key, value := range userLabels {
		userLabelsMetadata[key] = &domain.LabelMetadata{
			Value:  value,
			Source: domain.LabelSourceUser,
		}
	}

	// Merge policy and user labels
	allowOverride := false
	if p.AllowsUserLabels() {
		allowOverride = p.AppealConfig.UserLabelConfig.AllowOverride
	}
	mergedLabels := s.labelingService.MergeLabels(policyLabels, userLabelsMetadata, allowOverride)

	// Set both Labels (flat map) and LabelsMetadata (rich metadata)
	a.Labels = make(map[string]string)
	a.LabelsMetadata = mergedLabels
	for key, metadata := range mergedLabels {
		if metadata != nil {
			a.Labels[key] = metadata.Value
		}
	}

	return nil
}

func (s *Service) addCreatorDetails(ctx context.Context, a *domain.Appeal, p *domain.Policy) error {
	if p.IAM == nil {
		return nil
	}

	iamConfig, err := s.iam.ParseConfig(p.IAM)
	if err != nil {
		return fmt.Errorf("parsing policy.iam config: %w", err)
	}
	iamClient, err := s.iam.GetClient(iamConfig)
	if err != nil {
		return fmt.Errorf("initializing iam client: %w", err)
	}

	userDetails, err := iamClient.GetUser(a.CreatedBy)
	if err != nil {
		if p.AppealConfig != nil && p.AppealConfig.AllowCreatorDetailsFailure {
			s.logger.Warn(ctx, "unable to get creator details", "error", err)
			return nil
		}
		return fmt.Errorf("unable to get creator details: %w", err)
	}

	userDetailsMap, ok := userDetails.(map[string]interface{})
	if !ok {
		return nil
	}

	if p.IAM.Schema == nil {
		a.Creator = userDetailsMap
		return nil
	}

	creator := map[string]interface{}{}
	for schemaKey, targetKey := range p.IAM.Schema {
		if strings.Contains(targetKey, "$response") {
			params := map[string]interface{}{
				"response": userDetailsMap,
			}
			v, err := evaluator.Expression(targetKey).EvaluateWithVars(params)
			if err != nil {
				return fmt.Errorf("evaluating expression: %w", err)
			}
			creator[schemaKey] = v
		} else {
			creator[schemaKey] = userDetailsMap[targetKey]
		}
	}

	a.Creator = creator
	s.logger.Debug(ctx, "added creator details", "creator", creator)

	return nil
}

func addResource(a *domain.Appeal, resourcesMap map[string]*domain.Resource) error {
	r := resourcesMap[a.ResourceID]
	if r == nil {
		return ErrResourceNotFound
	} else if r.IsDeleted {
		return ErrResourceDeleted
	}

	a.Resource = r
	return nil
}

func getProvider(a *domain.Appeal, providersMap map[string]map[string]*domain.Provider) (*domain.Provider, error) {
	provider, ok := providersMap[a.Resource.ProviderType][a.Resource.ProviderURN]
	if !ok {
		return nil, fmt.Errorf("couldn't find details for provider %q: %w", a.Resource.ProviderType+" - "+a.Resource.ProviderURN, ErrProviderNotFound)
	}
	return provider, nil
}

func validateAppeal(a *domain.Appeal, pendingAppealsMap map[string]map[string]map[string]*domain.Appeal) error {
	accountID := strings.ToLower(a.AccountID)
	if pendingAppealsMap[accountID] != nil &&
		pendingAppealsMap[accountID][a.ResourceID] != nil &&
		pendingAppealsMap[accountID][a.ResourceID][a.Role] != nil {
		return fmt.Errorf("%w. appeal id: %q", ErrAppealDuplicate, pendingAppealsMap[accountID][a.ResourceID][a.Role].ID)
	}

	return nil
}

func (s *Service) getPermissions(ctx context.Context, pc *domain.ProviderConfig, resourceType, role string) ([]string, error) {
	permissions, err := s.providerService.GetPermissions(ctx, pc, resourceType, role)
	if err != nil {
		return nil, err
	}

	if permissions == nil {
		return nil, nil
	}

	strPermissions := []string{}
	for _, p := range permissions {
		strPermissions = append(strPermissions, fmt.Sprintf("%s", p))
	}
	return strPermissions, nil
}

// TODO(feature): add relation between new and revoked grant for traceability
func (s *Service) prepareGrant(ctx context.Context, appeal *domain.Appeal) (newGrant *domain.Grant, deactivatedGrant *domain.Grant, err error) {
	filter := domain.ListGrantsFilter{
		AccountIDs:  []string{appeal.AccountID},
		ResourceIDs: []string{appeal.ResourceID},
		Statuses:    []string{string(domain.GrantStatusActive)},
		Permissions: appeal.Permissions,
	}
	revocationReason := RevokeReasonForExtension
	if s.providerService.IsExclusiveRoleAssignment(ctx, appeal.Resource.ProviderType, appeal.Resource.Type) {
		filter.Permissions = nil
		revocationReason = RevokeReasonForOverride
	}

	activeGrants, err := s.grantService.List(ctx, filter)
	if err != nil {
		return nil, nil, fmt.Errorf("unable to retrieve existing active grants: %w", err)
	}

	if len(activeGrants) > 0 {
		deactivatedGrant = &activeGrants[0]
		if err := deactivatedGrant.Revoke(domain.SystemActorName, revocationReason); err != nil {
			return nil, nil, fmt.Errorf("revoking previous grant: %w", err)
		}
	}

	if err := appeal.Approve(); err != nil {
		return nil, nil, fmt.Errorf("activating appeal: %w", err)
	}

	grant, err := s.grantService.Prepare(ctx, *appeal)
	if err != nil {
		return nil, nil, err
	}

	return grant, deactivatedGrant, nil
}

func (s *Service) GetAppealsTotalCount(ctx context.Context, filters *domain.ListAppealsFilter) (int64, error) {
	return s.repo.GetAppealsTotalCount(ctx, filters)
}

func (s *Service) GenerateSummary(ctx context.Context, filters *domain.ListAppealsFilter) (*domain.SummaryResult, error) {
	return s.repo.GenerateSummary(ctx, filters)
}

func evaluateExpressionWithAppeal(a *domain.Appeal, expression string) (string, error) {
	if expression != "" && strings.Contains(expression, "$appeal") {
		appealMap, err := a.ToMap()
		if err != nil {
			return "", fmt.Errorf("error converting appeal to map: %w", err)
		}
		params := map[string]interface{}{"appeal": appealMap}
		evaluated, err := evaluator.Expression(expression).EvaluateWithVars(params)
		if err != nil {
			return "", fmt.Errorf("error evaluating expression %w", err)
		}
		evaluatedStr, ok := evaluated.(string)
		if !ok {
			return "", fmt.Errorf("expression must evaluate to a string")
		}
		return evaluatedStr, nil
	}
	return expression, nil
}

// executePostAppealHooks executes all post hooks for a requirement
// Similar pattern to getAppealMetadataSources but doesn't store response
func (s *Service) executePostAppealHooks(
	ctx context.Context,
	hooks []*domain.PostAppealHook,
	originalAppeal *domain.Appeal,
	additionalAppeals []*domain.Appeal,
	requirement *domain.Requirement,
	p *domain.Policy,
) error {
	if len(hooks) == 0 {
		return nil
	}
	// Use context.WithoutCancel to prevent post-hooks from being canceled
	// when the parent gRPC context times out. Post-hooks can be long-running
	// (e.g., creating additional resources, calling external services) and
	// should complete independently of the approval response timing.
	detachedCtx := context.WithoutCancel(ctx)
	eg, egctx := errgroup.WithContext(detachedCtx)

	for _, hook := range hooks {
		hook := hook
		eg.Go(func() error {
			switch hook.Type {
			case "http":
				var cfg policy.PostAppealHookConfigHTTP
				if err := mapstructure.Decode(hook.Config, &cfg); err != nil {
					return fmt.Errorf("error decoding hook %q config: %w", hook.Name, err)
				}

				if cfg.URL == "" {
					return fmt.Errorf("URL cannot be empty for http type in hook %q", hook.Name)
				}

				// Build expression evaluation context
				params := s.buildPostHookParams(originalAppeal, additionalAppeals, requirement, p)

				// Evaluate URL expression
				var err error
				cfg.URL, err = evaluateExpressionWithParams(params, cfg.URL)
				if err != nil {
					if cfg.AllowFailed {
						s.logger.Warn(egctx, "error evaluating URL for post hook (continuing due to allow_failed)",
							"hook_name", hook.Name,
							"error", err)
						return nil
					}
					return fmt.Errorf("error evaluating URL for hook %q: %w", hook.Name, err)
				}

				// Evaluate body expression
				if cfg.Body != "" {
					cfg.Body, err = evaluateExpressionWithParams(params, cfg.Body)
					if err != nil {
						if cfg.AllowFailed {
							s.logger.Warn(egctx, "error evaluating body for post hook (continuing due to allow_failed)",
								"hook_name", hook.Name,
								"error", err)
							return nil
						}
						return fmt.Errorf("error evaluating body for hook %q: %w", hook.Name, err)
					}
				}

				// Evaluate headers
				for key, value := range cfg.Headers {
					evaluatedValue, err := evaluateExpressionWithParams(params, value)
					if err != nil {
						if cfg.AllowFailed {
							s.logger.Warn(egctx, "error evaluating header for post hook (continuing due to allow_failed)",
								"hook_name", hook.Name,
								"header", key,
								"error", err)
							return nil
						}
						return fmt.Errorf("error evaluating header %q for hook %q: %w", key, hook.Name, err)
					}
					cfg.Headers[key] = evaluatedValue
				}

				// Create HTTP client (same pattern as metadata sources)
				clientCreator := &http.HttpClientCreatorStruct{}
				httpClient, err := http.NewHTTPClient(&cfg.HTTPClientConfig, clientCreator, "PostAppealHook")
				if err != nil {
					if cfg.AllowFailed {
						s.logger.Warn(egctx, "error creating http client for post hook (continuing due to allow_failed)",
							"hook_name", hook.Name,
							"error", err)
						return nil
					}
					return fmt.Errorf("error creating http client for hook %q: %w", hook.Name, err)
				}

				s.logger.Info(egctx, "executing post appeal hook",
					"hook_name", hook.Name,
					"url", cfg.URL,
					"method", cfg.Method,
					"original_appeal_id", originalAppeal.ID,
					"additional_appeals_count", len(additionalAppeals))

				// Make HTTP request
				res, err := httpClient.MakeRequest(egctx)
				if err != nil {
					if cfg.AllowFailed {
						s.logger.Warn(egctx, "post hook request failed (continuing due to allow_failed)",
							"hook_name", hook.Name,
							"error", err)
						return nil
					}
					return fmt.Errorf("error making request for hook %q: %w", hook.Name, err)
				}

				// Check status code
				if res.StatusCode < 200 || res.StatusCode >= 300 {
					body, _ := io.ReadAll(res.Body)
					res.Body.Close()

					if cfg.AllowFailed {
						s.logger.Warn(egctx, "post hook returned error status (continuing due to allow_failed)",
							"hook_name", hook.Name,
							"status_code", res.StatusCode,
							"response_body", string(body))
						return nil
					}
					return fmt.Errorf("hook %q returned error status %d: %s", hook.Name, res.StatusCode, string(body))
				}

				s.logger.Info(egctx, "post appeal hook executed successfully",
					"hook_name", hook.Name,
					"status_code", res.StatusCode)

				return nil

			default:
				return fmt.Errorf("invalid post hook type: %s", hook.Type)
			}
		})
	}

	if err := eg.Wait(); err != nil {
		return err
	}

	return nil
}

// buildPostHookParams builds expression evaluation parameters for post hooks
func (s *Service) buildPostHookParams(
	originalAppeal *domain.Appeal,
	additionalAppeals []*domain.Appeal,
	requirement *domain.Requirement,
	p *domain.Policy,
) map[string]interface{} {
	originalAppealJSON, _ := json.Marshal(originalAppeal)
	var originalAppealMap map[string]interface{}
	json.Unmarshal(originalAppealJSON, &originalAppealMap)
	// Convert additional appeals to interface{} for expression evaluation
	appealsData := make([]interface{}, len(additionalAppeals))
	for i, appeal := range additionalAppeals {
		appealJSON, _ := json.Marshal(appeal)
		var appealMap map[string]interface{}
		json.Unmarshal(appealJSON, &appealMap)
		appealsData[i] = appealMap
	}

	return map[string]interface{}{
		"appeal":             originalAppealMap,
		"additional_appeals": appealsData,
		"requirement":        requirement,
		"policy":             p,
	}
}

// evaluateExpressionWithParams evaluates an expression with given parameters
// Similar to evaluateExpressionWithAppeal but with custom params
func evaluateExpressionWithParams(params map[string]interface{}, expr string) (string, error) {
	result, err := evaluator.Expression(expr).EvaluateWithVars(params)
	if err != nil {
		return "", err
	}

	// Convert result to string
	switch v := result.(type) {
	case string:
		return v, nil
	case []byte:
		return string(v), nil
	default:
		// Marshal to JSON string for complex types
		jsonBytes, err := json.Marshal(v)
		if err != nil {
			return "", fmt.Errorf("failed to convert result to string: %w", err)
		}
		return string(jsonBytes), nil
	}
}
