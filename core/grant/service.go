package grant

import (
	"context"
	"fmt"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/bearaujus/bjson"
	"github.com/go-playground/validator/v10"

	guardianv1beta1 "github.com/goto/guardian/api/proto/gotocompany/guardian/v1beta1"
	"github.com/goto/guardian/domain"
	"github.com/goto/guardian/pkg/log"
	slicesUtil "github.com/goto/guardian/pkg/slices"
	"github.com/goto/guardian/plugins/notifiers"
	"github.com/goto/guardian/utils"
)

const (
	AuditKeyRevoke          = "grant.revoke"
	AuditKeyUpdate          = "grant.update"
	AuditKeyRestore         = "grant.restore"
	AuditKeyDriftRemediaton = "grant.drift_remediation"

	// guardianProviderType is the provider type for Guardian-managed resources (e.g. packages).
	// GrantAccess for this provider is a no-op, so automatic drift remediation is not supported.
	guardianProviderType                     = "guardian"
	guardianGroupTypePackageUser             = "package_user"
	guardianGroupTypePackageAccessBotRAMRole = "package_access_bot_ram_role"
)

//go:generate mockery --name=repository --exported --with-expecter
type repository interface {
	List(context.Context, domain.ListGrantsFilter) ([]domain.Grant, error)
	GenerateSummary(context.Context, domain.ListGrantsFilter) (*domain.SummaryResult, error)
	GetByID(context.Context, string) (*domain.Grant, error)
	Update(context.Context, *domain.Grant) error
	Patch(context.Context, domain.GrantUpdate) error
	BulkUpsert(context.Context, []*domain.Grant) error
	GetGrantsTotalCount(context.Context, domain.ListGrantsFilter) (int64, error)
	ListUserRoles(context.Context, string) ([]string, error)
	Create(context.Context, *domain.Grant) error
}

//go:generate mockery --name=appealService --exported --with-expecter
type appealService interface {
	Find(ctx context.Context, filters *domain.ListAppealsFilter) ([]*domain.Appeal, error)
}

//go:generate mockery --name=providerService --exported --with-expecter
type providerService interface {
	GetByID(context.Context, string) (*domain.Provider, error)
	GrantAccess(context.Context, domain.Grant) error
	RevokeAccess(context.Context, domain.Grant) error
	Find(context.Context, domain.ListProvidersFilter) ([]*domain.Provider, error)
	ListAccess(context.Context, domain.Provider, []*domain.Resource) (domain.MapResourceAccess, error)
	ListActivities(context.Context, domain.Provider, domain.ListActivitiesFilter) ([]*domain.Activity, error)
	CorrelateGrantActivities(context.Context, domain.Provider, []*domain.Grant, []*domain.Activity) error
}

//go:generate mockery --name=resourceService --exported --with-expecter
type resourceService interface {
	Find(context.Context, domain.ListResourcesFilter) ([]*domain.Resource, error)
}

//go:generate mockery --name=auditLogger --exported --with-expecter
type auditLogger interface {
	Log(ctx context.Context, action string, data interface{}) error
}

//go:generate mockery --name=notifier --exported --with-expecter
type notifier interface {
	notifiers.Client
}

//go:generate mockery --name=alertManager --exported --with-expecter
type alertManager interface {
	NotifyDriftCheck(ctx context.Context, adminTeam string, issues []domain.GrantDriftIssue) []error
}

type grantCreation struct {
	AppealStatus string `validate:"required,eq=approved"`
	AccountID    string `validate:"required"`
	AccountType  string `validate:"required"`
	ResourceID   string `validate:"required"`
}

type Service struct {
	repo            repository
	AppealService   appealService
	providerService providerService
	resourceService resourceService

	notifier     notifier
	alertManager alertManager
	validator    *validator.Validate
	logger       log.Logger
	auditLogger  auditLogger
}

type ServiceDeps struct {
	Repository      repository
	ProviderService providerService
	ResourceService resourceService

	Notifier     notifier
	AlertManager alertManager
	Validator    *validator.Validate
	Logger       log.Logger
	AuditLogger  auditLogger
}

func NewService(deps ServiceDeps) *Service {
	return &Service{
		repo:            deps.Repository,
		providerService: deps.ProviderService,
		resourceService: deps.ResourceService,

		notifier:     deps.Notifier,
		alertManager: deps.AlertManager,
		validator:    deps.Validator,
		logger:       deps.Logger,
		auditLogger:  deps.AuditLogger,
	}
}

func (s *Service) SetAppealService(a appealService) {
	s.AppealService = a
}

func (s *Service) List(ctx context.Context, filter domain.ListGrantsFilter) ([]domain.Grant, error) {
	grants, err := s.repo.List(ctx, filter)
	if err != nil {
		return nil, err
	}

	if !filter.WithPendingAppeal || len(grants) == 0 {
		return grants, nil
	}

	accountIDs, resourceIDs, roles := make([]string, len(grants)), make([]string, len(grants)), make([]string, len(grants))
	for i, m := range grants {
		accountIDs[i] = m.AccountID
		resourceIDs[i] = m.ResourceID
		roles[i] = m.Role
	}

	pendingAppeals, err := s.AppealService.Find(ctx, &domain.ListAppealsFilter{
		Statuses:    []string{domain.AppealStatusPending},
		AccountIDs:  slicesUtil.GenericsStandardizeSlice(accountIDs),
		ResourceIDs: slicesUtil.GenericsStandardizeSlice(resourceIDs),
		Roles:       slicesUtil.GenericsStandardizeSlice(roles),
	})
	if err != nil {
		return nil, err
	}

	for i, g := range grants {
		for _, appeal := range pendingAppeals {
			if appeal.Resource == nil {
				break
			}
			if strings.EqualFold(g.ResourceID, appeal.ResourceID) &&
				strings.EqualFold(g.AccountID, appeal.AccountID) &&
				strings.EqualFold(g.Role, appeal.Role) {
				g.PendingAppealID = appeal.ID
				grants[i] = g
				break
			}
		}
	}

	return grants, nil
}

func (s *Service) GenerateSummary(ctx context.Context, filter domain.ListGrantsFilter) (*domain.SummaryResult, error) {
	return s.repo.GenerateSummary(ctx, filter)
}

func (s *Service) GenerateUserExcludedGrantIDsForSmartInactiveGrants(ctx context.Context, filter domain.ListGrantsFilter) ([]string, error) {
	owner := strings.ToLower(filter.Owner)
	if filter.CreatedBy != "" {
		owner = strings.ToLower(filter.CreatedBy)
	}

	if filter.UserInactiveGrantPolicy != guardianv1beta1.ListUserGrantsRequest_INACTIVE_GRANT_POLICY_SMART ||
		owner == "" ||
		(len(filter.Statuses) != 0 && !slices.Contains(filter.Statuses, string(domain.GrantStatusInactive))) {
		return nil, nil
	}

	// get inactive grants
	inf := filter
	inf.Offset, inf.Size, inf.OrderBy = 0, 0, nil
	inf.Statuses = []string{string(domain.GrantStatusInactive)}
	inactiveGrants, err := s.repo.List(ctx, inf)
	if err != nil {
		return nil, err
	}

	// get active grants
	acf := filter
	acf.Offset, acf.Size, acf.OrderBy = 0, 0, nil
	acf.Statuses = []string{string(domain.GrantStatusActive)}
	activeGrants, err := s.repo.List(ctx, acf)
	if err != nil {
		return nil, err
	}

	return smartExcludedGrantIDs(activeGrants, inactiveGrants), nil
}

// ignoredInactiveGrantFilterKeys are fields that are always reset in the scoped inner queries
// (pagination and status) and are therefore meaningless as scoping keys.
var ignoredInactiveGrantFilterKeys = map[string]struct{}{
	"offset":   {},
	"size":     {},
	"order_by": {},
	"statuses": {},
}

// invalidInactiveGrantFilterKeys are fields that exist on ListGrantsFilter but must never be used
// as scoping keys — either because they are policy/meta fields that would create circular logic,
// or because they are output-control fields unrelated to grant scoping.
var invalidInactiveGrantFilterKeys = map[string]struct{}{
	"inactive_grant_policy":      {},
	"inactive_grant_filter_keys": {},
	"user_inactive_grant_policy": {},
	"with_approvals":             {},
	"field_masks":                {},
	"summary_group_bys":          {},
	"summary_labels":             {},
	"summary_labels_v2":          {},
	"exclude_empty_appeal":       {},
}

// GenerateExcludedGrantIDsForSmartInactiveGrants handles the group/resource/provider-scoped
// smart inactive grant dedup triggered by InactiveGrantPolicy=SMART
// InactiveGrantFilterKeys must be non-empty (and each key must have a corresponding non-empty
// value in the filter) to prevent accidentally fetching all grants at once.
// Keys in ignoredInactiveGrantFilterKeys (offset, size, order_by, statuses) are silently
// skipped — they are always reset in the inner queries and do not count toward the non-empty
// requirement.
// Keys in invalidInactiveGrantFilterKeys are rejected with an explicit error.
func (s *Service) GenerateExcludedGrantIDsForSmartInactiveGrants(ctx context.Context, filter domain.ListGrantsFilter) ([]string, error) {
	if filter.InactiveGrantPolicy != guardianv1beta1.ListGrantsRequest_INACTIVE_GRANT_POLICY_SMART ||
		(len(filter.Statuses) != 0 && !slices.Contains(filter.Statuses, string(domain.GrantStatusInactive))) {
		return nil, nil
	}

	// Strip pagination/status keys that are always reset in the inner queries.
	// Reject keys that are policy/meta/output-control fields — they are not valid scoping keys.
	effectiveKeys := make([]string, 0, len(filter.InactiveGrantFilterKeys))
	for _, key := range filter.InactiveGrantFilterKeys {
		if _, invalid := invalidInactiveGrantFilterKeys[key]; invalid {
			return nil, fmt.Errorf("inactive_grant_filter_keys contains %q which is not a valid scoping key", key)
		}
		if _, ignored := ignoredInactiveGrantFilterKeys[key]; !ignored {
			effectiveKeys = append(effectiveKeys, key)
		}
	}

	if len(effectiveKeys) == 0 {
		return nil, fmt.Errorf("inactive_grant_filter_keys must not be empty when using SMART inactive grant policy")
	}

	// Serialize the filter so we can inspect and copy individual fields by key name.
	bjFilter, err := bjson.NewBJSON(filter)
	if err != nil {
		return nil, fmt.Errorf("failed to build filter representation: %w", err)
	}
	for _, key := range effectiveKeys {
		elem, err := bjFilter.GetElement(key)
		if err != nil || elem.Len() == 0 {
			return nil, fmt.Errorf("inactive_grant_filter_keys contains %q but filter has no value", key)
		}
	}

	// get inactive grants
	inf := filter
	inf.Offset, inf.Size, inf.OrderBy = 0, 0, nil
	inf.Statuses = []string{string(domain.GrantStatusInactive)}
	inactiveGrants, err := s.repo.List(ctx, inf)
	if err != nil {
		return nil, err
	}

	// get active grants
	acf := filter
	acf.Offset, acf.Size, acf.OrderBy = 0, 0, nil
	acf.Statuses = []string{string(domain.GrantStatusActive)}
	activeGrants, err := s.repo.List(ctx, acf)
	if err != nil {
		return nil, err
	}

	return smartExcludedGrantIDs(activeGrants, inactiveGrants), nil
}

// smartExcludedGrantIDs returns the IDs of inactive grants that should be excluded.
// It excludes inactive grants that have an active counterpart (same resource+account+role),
// and for duplicate inactives with no active counterpart, keeps only the latest; excludes the rest.
func smartExcludedGrantIDs(activeGrants, inactiveGrants []domain.Grant) []string {
	// Exclude inactive grants that have an active counterpart (same resource+account+role).
	activeMap := make(map[string]struct{})
	for _, ag := range activeGrants {
		key := ag.ResourceID + ":" + ag.AccountID + ":" + ag.Role
		activeMap[key] = struct{}{}
	}
	var ret []string
	for _, ig := range inactiveGrants {
		key := ig.ResourceID + ":" + ig.AccountID + ":" + ig.Role
		if _, found := activeMap[key]; found {
			ret = append(ret, ig.ID)
		}
	}

	// For duplicate inactives with no active counterpart, keep only the latest; exclude the rest.
	type inactiveData struct {
		latest      domain.Grant
		excludedIDs []string
	}
	group := make(map[string]*inactiveData)

	for _, ig := range inactiveGrants {
		ig := ig // capture loop variable
		key := ig.ResourceID + ":" + ig.AccountID + ":" + ig.Role
		if _, found := activeMap[key]; found {
			continue // skip already excluded by active
		}
		d := group[key]
		if d == nil {
			group[key] = &inactiveData{latest: ig}
			continue
		}
		if ig.UpdatedAt.After(d.latest.UpdatedAt) {
			d.excludedIDs = append(d.excludedIDs, d.latest.ID)
			d.latest = ig
		} else {
			d.excludedIDs = append(d.excludedIDs, ig.ID)
		}
	}

	for _, d := range group {
		ret = append(ret, d.excludedIDs...)
	}

	return slicesUtil.GenericsStandardizeSlice(ret)
}

func (s *Service) GetByID(ctx context.Context, id string) (*domain.Grant, error) {
	if id == "" {
		return nil, ErrEmptyIDParam
	}
	return s.repo.GetByID(ctx, id)
}

func (s *Service) Create(ctx context.Context, grant *domain.Grant) error {
	return s.repo.Create(ctx, grant)
}

func (s *Service) Update(ctx context.Context, payload *domain.GrantUpdate) (*domain.Grant, error) {
	grant, err := s.GetByID(ctx, payload.ID)
	if err != nil {
		return nil, fmt.Errorf("getting grant details: %w", err)
	}
	previousOwner := grant.Owner

	if err := payload.Validate(*grant); err != nil {
		return nil, fmt.Errorf("%w: %s", domain.ErrInvalidGrantUpdateRequest, err)
	}

	if payload.IsUpdatingExpirationDate() {
		falseBool := false
		payload.IsPermanent = &falseBool
	}
	if err := s.repo.Patch(ctx, *payload); err != nil {
		return nil, err
	}

	latestGrant, err := s.GetByID(ctx, grant.ID)
	if err != nil {
		return nil, err
	}

	s.logger.Info(ctx, "grant updated", "grant_id", grant.ID, "updatedGrant", latestGrant)

	go func() {
		diff, err := latestGrant.Compare(grant, payload.Actor)
		if err != nil {
			s.logger.Error(ctx, "failed to compare grant", "error", err)
			return
		}

		ctx := context.WithoutCancel(ctx)
		if err := s.auditLogger.Log(ctx, AuditKeyUpdate, map[string]interface{}{
			"grant_id":      payload.ID,
			"payload":       payload,
			"updated_grant": latestGrant,
			"diff":          diff,
		}); err != nil {
			s.logger.Error(ctx, "failed to record audit log", "error", err)
		}
	}()

	if previousOwner != latestGrant.Owner {
		go func() {
			message := domain.NotificationMessage{
				Type: domain.NotificationTypeGrantOwnerChanged,
				Variables: map[string]interface{}{
					"grant_id":       grant.ID,
					"previous_owner": previousOwner,
					"new_owner":      latestGrant.Owner,
				},
			}
			notifications := []domain.Notification{{
				User: latestGrant.Owner,
				Labels: map[string]string{
					"appeal_id": grant.AppealID,
					"grant_id":  grant.ID,
				},
				Message: message,
			}}
			if previousOwner != "" {
				notifications = append(notifications, domain.Notification{
					User: previousOwner,
					Labels: map[string]string{
						"appeal_id": grant.AppealID,
						"grant_id":  grant.ID,
					},
					Message: message,
				})
			}
			ctx := context.WithoutCancel(ctx)
			if errs := s.notifier.Notify(ctx, notifications); errs != nil {
				for _, err1 := range errs {
					s.logger.Error(ctx, "failed to send notifications", "error", err1.Error())
				}
			}
		}()
	}

	return latestGrant, nil
}

func (s *Service) Prepare(ctx context.Context, appeal domain.Appeal) (*domain.Grant, error) {
	// validation
	if err := s.validator.Struct(grantCreation{
		AppealStatus: appeal.Status,
		AccountID:    appeal.AccountID,
		AccountType:  appeal.AccountType,
		ResourceID:   appeal.ResourceID,
	}); err != nil {
		return nil, fmt.Errorf("validating appeal: %w", err)
	}

	// converting aapeal into a new grant
	return appeal.ToGrant()
}

func (s *Service) Revoke(ctx context.Context, id, actor, reason string, opts ...Option) (*domain.Grant, error) {
	grant, err := s.GetByID(ctx, id)
	if err != nil {
		return nil, fmt.Errorf("getting grant details: %w", err)
	}

	options := s.getOptions(opts...)
	if options.dryRun {
		return grant, nil
	}

	revokedGrant := &domain.Grant{}
	*revokedGrant = *grant
	if err := grant.Revoke(actor, reason); err != nil {
		return nil, err
	}
	if err := s.repo.Update(ctx, grant); err != nil {
		return nil, fmt.Errorf("updating grant record in db: %w", err)
	}

	if !options.skipRevokeInProvider {
		if err := s.providerService.RevokeAccess(ctx, *grant); err != nil {
			if err := s.repo.Update(ctx, grant); err != nil {
				return nil, fmt.Errorf("failed to rollback grant status: %w", err)
			}
			return nil, fmt.Errorf("removing grant in provider: %w", err)
		}
	}

	if !options.skipNotification {
		notifications := []domain.Notification{{
			User: grant.CreatedBy,
			Labels: map[string]string{
				"appeal_id": grant.AppealID,
				"grant_id":  grant.ID,
			},
			Message: domain.NotificationMessage{
				Type: domain.NotificationTypeAccessRevoked,
				Variables: map[string]interface{}{
					"resource_name": fmt.Sprintf("%s (%s: %s)", grant.Resource.Name, grant.Resource.ProviderType, grant.Resource.URN),
					"role":          grant.Role,
					"account_type":  grant.AccountType,
					"account_id":    grant.AccountID,
					"requestor":     grant.Owner,
					"revoke_reason": grant.RevokeReason,
				},
			},
		}}
		go func() {
			ctx := context.WithoutCancel(ctx)
			if errs := s.notifier.Notify(ctx, notifications); errs != nil {
				for _, err1 := range errs {
					s.logger.Error(ctx, "failed to send notifications", "error", err1.Error())
				}
			}
		}()
	}

	s.logger.Info(ctx, "grant revoked", "grant_id", id)

	go func() {
		ctx := context.WithoutCancel(ctx)
		if err := s.auditLogger.Log(ctx, AuditKeyRevoke, map[string]interface{}{
			"grant_id": id,
			"reason":   reason,
		}); err != nil {
			s.logger.Error(ctx, "failed to record audit log", "error", err)
		}
	}()

	return grant, nil
}

func (s *Service) Restore(ctx context.Context, id, actor, reason string) (*domain.Grant, error) {
	originalGrant, err := s.GetByID(ctx, id)
	if err != nil {
		return nil, fmt.Errorf("getting grant details: %w", err)
	}

	grant := &domain.Grant{}
	*grant = *originalGrant // copy values

	if err := grant.Restore(actor, reason); err != nil {
		return nil, err
	}

	if err := s.repo.Update(ctx, grant); err != nil {
		return nil, fmt.Errorf("updating grant record in db: %w", err)
	}

	if err := s.providerService.GrantAccess(ctx, *grant); err != nil {
		if err := s.repo.Update(ctx, originalGrant); err != nil {
			return nil, fmt.Errorf("failed to rollback grant record after restore failed: %w", err)
		}
		return nil, fmt.Errorf("granting access in provider: %w", err)
	}

	go func() {
		ctx := context.WithoutCancel(ctx)
		if err := s.auditLogger.Log(ctx, AuditKeyRestore, map[string]interface{}{
			"grant_id": id,
			"reason":   reason,
		}); err != nil {
			s.logger.Error(ctx, "failed to record audit log", "error", err)
		}
	}()

	return grant, nil
}

func (s *Service) BulkRevoke(ctx context.Context, filter domain.RevokeGrantsFilter, actor, reason string) ([]*domain.Grant, error) {
	if filter.AccountIDs == nil || len(filter.AccountIDs) == 0 {
		return nil, fmt.Errorf("account_ids is required")
	}

	grants, err := s.List(ctx, domain.ListGrantsFilter{
		Statuses:      []string{string(domain.GrantStatusActive)},
		AccountIDs:    filter.AccountIDs,
		ProviderTypes: filter.ProviderTypes,
		ProviderURNs:  filter.ProviderURNs,
		ResourceTypes: filter.ResourceTypes,
		ResourceURNs:  filter.ResourceURNs,
	})
	if err != nil {
		return nil, fmt.Errorf("listing active grants: %w", err)
	}
	if len(grants) == 0 {
		return nil, nil
	}

	result := make([]*domain.Grant, 0)
	batchSize := 10
	timeLimiter := make(chan int, batchSize)

	for i := 1; i <= batchSize; i++ {
		timeLimiter <- i
	}

	go func() {
		for range time.Tick(1 * time.Second) {
			for i := 1; i <= batchSize; i++ {
				timeLimiter <- i
			}
		}
	}()

	totalRequests := len(grants)
	done := make(chan *domain.Grant, totalRequests)
	resourceGrantMap := make(map[string][]*domain.Grant, 0)

	for i, grant := range grants {
		var resourceGrants []*domain.Grant
		var ok bool
		if resourceGrants, ok = resourceGrantMap[grant.ResourceID]; ok {
			resourceGrants = append(resourceGrants, &grants[i])
		} else {
			resourceGrants = []*domain.Grant{&grants[i]}
		}
		resourceGrantMap[grant.ResourceID] = resourceGrants
	}

	for _, resourceGrants := range resourceGrantMap {
		go s.expiredInActiveUserAccess(ctx, timeLimiter, done, actor, reason, resourceGrants)
	}

	var successRevoke []string
	var failedRevoke []string
	for {
		select {
		case grant := <-done:
			if grant.Status == domain.GrantStatusInactive {
				successRevoke = append(successRevoke, grant.ID)
			} else {
				failedRevoke = append(failedRevoke, grant.ID)
			}
			result = append(result, grant)
			if len(result) == totalRequests {
				s.logger.Info(ctx, "successful grant revocation", "count", len(successRevoke), "ids", successRevoke)
				if len(failedRevoke) > 0 {
					s.logger.Info(ctx, "failed grant revocation", "count", len(failedRevoke), "ids", failedRevoke)
				}
				return result, nil
			}
		}
	}
}

func (s *Service) expiredInActiveUserAccess(ctx context.Context, timeLimiter chan int, done chan *domain.Grant, actor string, reason string, grants []*domain.Grant) {
	for _, grant := range grants {
		<-timeLimiter

		revokedGrant := &domain.Grant{}
		*revokedGrant = *grant
		if err := revokedGrant.Revoke(actor, reason); err != nil {
			s.logger.Error(ctx, "failed to revoke grant", "id", grant.ID, "error", err)
			return
		}
		if err := s.providerService.RevokeAccess(ctx, *grant); err != nil {
			done <- grant
			s.logger.Error(ctx, "failed to revoke grant in provider", "id", grant.ID, "error", err)
			return
		}

		revokedGrant.Status = domain.GrantStatusInactive
		if err := s.repo.Update(ctx, revokedGrant); err != nil {
			done <- grant
			s.logger.Error(ctx, "failed to update access-revoke status", "id", grant.ID, "error", err)
			return
		} else {
			done <- revokedGrant
			s.logger.Info(ctx, "grant revoked", "id", grant.ID)
		}
	}
}

type ImportFromProviderCriteria struct {
	ProviderID    string `validate:"required"`
	ResourceIDs   []string
	ResourceTypes []string
	ResourceURNs  []string
}

func (s *Service) ImportFromProvider(ctx context.Context, criteria ImportFromProviderCriteria) ([]*domain.Grant, error) {
	p, err := s.providerService.GetByID(ctx, criteria.ProviderID)
	if err != nil {
		return nil, fmt.Errorf("getting provider details: %w", err)
	}

	listResourcesFilter := domain.ListResourcesFilter{
		ProviderType: p.Type,
		ProviderURN:  p.URN,
	}
	listGrantsFilter := domain.ListGrantsFilter{
		Statuses:      []string{string(domain.GrantStatusActive)},
		ProviderTypes: []string{p.Type},
		ProviderURNs:  []string{p.URN},
	}
	if criteria.ResourceIDs != nil {
		listResourcesFilter.IDs = criteria.ResourceIDs
		listGrantsFilter.ResourceIDs = criteria.ResourceIDs
	} else {
		listResourcesFilter.ResourceTypes = criteria.ResourceTypes
		listResourcesFilter.ResourceURNs = criteria.ResourceURNs

		listGrantsFilter.ResourceTypes = criteria.ResourceTypes
		listGrantsFilter.ResourceURNs = criteria.ResourceURNs
	}
	resources, err := s.resourceService.Find(ctx, listResourcesFilter)
	if err != nil {
		return nil, fmt.Errorf("getting resources: %w", err)
	}

	resourceAccess, err := s.providerService.ListAccess(ctx, *p, resources)
	if err != nil {
		return nil, fmt.Errorf("fetching access from provider: %w", err)
	}

	resourceConfigs := make(map[string]*domain.ResourceConfig)
	for _, rc := range p.Config.Resources {
		resourceConfigs[rc.Type] = rc
	}

	resourcesMap := make(map[string]*domain.Resource)
	for _, r := range resources {
		resourcesMap[r.URN] = r
	}

	activeGrants, err := s.repo.List(ctx, listGrantsFilter)
	if err != nil {
		return nil, fmt.Errorf("getting active grants: %w", err)
	}
	// map[resourceURN]map[accounttype:accountId]map[permissionsKey]grant
	activeGrantsMap := map[string]map[string]map[string]*domain.Grant{}
	for i, g := range activeGrants {
		if activeGrantsMap[g.Resource.URN] == nil {
			activeGrantsMap[g.Resource.URN] = map[string]map[string]*domain.Grant{}
		}

		accountSignature := getAccountSignature(g.AccountType, g.AccountID)
		if activeGrantsMap[g.Resource.URN][accountSignature] == nil {
			activeGrantsMap[g.Resource.URN][accountSignature] = map[string]*domain.Grant{}
		}

		activeGrantsMap[g.Resource.URN][accountSignature][g.PermissionsKey()] = &activeGrants[i]
	}

	var newAndUpdatedGrants []*domain.Grant
	for rURN, accessEntries := range resourceAccess {
		resource, ok := resourcesMap[rURN]
		if !ok {
			continue // skip access for resources that not yet added to guardian
		}

		importedGrants := []*domain.Grant{}
		for accountSignature, accessEntries := range groupAccessEntriesByAccount(accessEntries) {
			// convert access entries to grants
			var grants []*domain.Grant
			for _, ae := range accessEntries {
				g := ae.ToGrant(*resource)
				grants = append(grants, &g)
			}

			// group grants for the same account (accountGrants) by provider role
			rc := resourceConfigs[resource.Type]
			grants = reduceGrantsByProviderRole(*rc, grants)
			for i, g := range grants {
				key := g.PermissionsKey()
				if existingGrant, ok := activeGrantsMap[rURN][accountSignature][key]; ok {
					// replace imported grant values with existing grant
					*grants[i] = *existingGrant

					// remove updated grant from active grants map
					delete(activeGrantsMap[rURN][accountSignature], key)
				}
			}

			importedGrants = append(importedGrants, grants...)
		}

		if len(importedGrants) > 0 {
			if err := s.repo.BulkUpsert(ctx, importedGrants); err != nil {
				return nil, fmt.Errorf("inserting new and updated grants into the db for %q: %w", rURN, err)
			}
			newAndUpdatedGrants = append(newAndUpdatedGrants, importedGrants...)
		}
	}

	// mark remaining active grants as inactive
	var deactivatedGrants []*domain.Grant
	for _, v := range activeGrantsMap {
		for _, v2 := range v {
			for _, g := range v2 {
				g.StatusInProvider = domain.GrantStatusInactive
				deactivatedGrants = append(deactivatedGrants, g)
			}
		}
	}
	if len(deactivatedGrants) > 0 {
		if err := s.repo.BulkUpsert(ctx, deactivatedGrants); err != nil {
			return nil, fmt.Errorf("updating grants provider status: %w", err)
		}
	}

	return newAndUpdatedGrants, nil
}

func (s *Service) DormancyCheck(ctx context.Context, criteria domain.DormancyCheckCriteria) error {
	if err := criteria.Validate(); err != nil {
		return fmt.Errorf("invalid dormancy check criteria: %w", err)
	}
	startDate := time.Now().Add(-criteria.Period)

	provider, err := s.providerService.GetByID(ctx, criteria.ProviderID)
	if err != nil {
		return fmt.Errorf("getting provider details: %w", err)
	}

	s.logger.Info(ctx, "getting active grants", "provider_urn", provider.URN)
	grants, err := s.List(ctx, domain.ListGrantsFilter{
		Statuses:      []string{string(domain.GrantStatusActive)}, // TODO: evaluate later to use status_in_provider
		ProviderTypes: []string{provider.Type},
		ProviderURNs:  []string{provider.URN},
		CreatedAtLte:  startDate,
	})
	if err != nil {
		return fmt.Errorf("listing active grants: %w", err)
	}
	if len(grants) == 0 {
		s.logger.Info(ctx, "no active grants found", "provider_urn", provider.URN)
		return nil
	}
	grantIDs := getGrantIDs(grants)
	s.logger.Info(ctx, fmt.Sprintf("found %d active grants", len(grants)), "grant_ids", grantIDs, "provider_urn", provider.URN)

	var accountIDs []string
	for _, g := range grants {
		accountIDs = append(accountIDs, g.AccountID)
	}
	accountIDs = slicesUtil.UniqueStringSlice(accountIDs)

	s.logger.Info(ctx, "getting activities", "provider_urn", provider.URN)
	activities, err := s.providerService.ListActivities(ctx, *provider, domain.ListActivitiesFilter{
		AccountIDs:   accountIDs,
		TimestampGte: &startDate,
	})
	if err != nil {
		return fmt.Errorf("listing activities for provider %q: %w", provider.URN, err)
	}
	s.logger.Info(ctx, fmt.Sprintf("found %d activities", len(activities)), "provider_urn", provider.URN)

	grantsPointer := make([]*domain.Grant, len(grants))
	for i, g := range grants {
		g := g
		grantsPointer[i] = &g
	}
	if err := s.providerService.CorrelateGrantActivities(ctx, *provider, grantsPointer, activities); err != nil {
		return fmt.Errorf("correlating grant activities: %w", err)
	}

	s.logger.Info(ctx, "checking grants dormancy...", "provider_urn", provider.URN)
	var dormantGrants []*domain.Grant
	var dormantGrantsIDs []string
	var dormantGrantsByOwner = map[string][]*domain.Grant{}
	for _, g := range grantsPointer {
		if len(g.Activities) == 0 {
			g.ExpirationDateReason = fmt.Sprintf("%s: %s", domain.GrantExpirationReasonDormant, criteria.RetainDuration)
			newExpDate := time.Now().Add(criteria.RetainDuration)
			g.ExpirationDate = &newExpDate
			g.IsPermanent = false

			dormantGrants = append(dormantGrants, g)
			dormantGrantsIDs = append(dormantGrantsIDs, g.ID)

			dormantGrantsByOwner[g.Owner] = append(dormantGrantsByOwner[g.Owner], g)
		}
	}
	s.logger.Info(ctx, fmt.Sprintf("found %d dormant grants", len(dormantGrants)), "grant_ids", dormantGrantsIDs, "provider_urn", provider.URN)

	if criteria.DryRun {
		s.logger.Info(ctx, "dry run mode, skipping updating grants expiration date", "provider_urn", provider.URN)
		return nil
	}

	if err := s.repo.BulkUpsert(ctx, dormantGrants); err != nil {
		return fmt.Errorf("updating grants expiration date: %w", err)
	}

	go func() {
		ctx := context.WithoutCancel(ctx)
		var notifications []domain.Notification
	prepare_notifications:
		for owner, grants := range dormantGrantsByOwner {
			var grantsMap []map[string]interface{}
			var grantIDs []string

			for _, g := range grants {
				grantMap, err := utils.StructToMap(g)
				if err != nil {
					s.logger.Error(ctx, "failed to convert grant to map", "error", err)
					continue prepare_notifications
				}
				grantsMap = append(grantsMap, grantMap)
			}

			notifications = append(notifications, domain.Notification{
				User: owner,
				Labels: map[string]string{
					"owner":     owner,
					"grant_ids": strings.Join(grantIDs, ", "),
				},
				Message: domain.NotificationMessage{
					Type: domain.NotificationTypeUnusedGrant,
					Variables: map[string]interface{}{
						"dormant_grants":       grantsMap,
						"period":               criteria.Period.String(),
						"retain_duration":      criteria.RetainDuration.String(),
						"start_date_formatted": startDate.Format("Jan 02, 2006 15:04:05 UTC"),
					},
				},
			})
		}

		if errs := s.notifier.Notify(ctx, notifications); errs != nil {
			for _, err1 := range errs {
				s.logger.Error(ctx, "failed to send notifications", "error", err1.Error(), "provider_urn", provider.URN)
			}
		}
	}()

	return nil
}

func getAccountSignature(accountType, accountID string) string {
	return fmt.Sprintf("%s:%s", accountType, accountID)
}

func groupAccessEntriesByAccount(accessEntries []domain.AccessEntry) map[string][]domain.AccessEntry {
	result := map[string][]domain.AccessEntry{}
	for _, ae := range accessEntries {
		accountSignature := getAccountSignature(ae.AccountType, ae.AccountID)
		result[accountSignature] = append(result[accountSignature], ae)
	}
	return result
}

// reduceGrantsByProviderRole reduces grants based on configured roles in the provider's resource config and returns reduced grants containing the Role according to the resource config
func reduceGrantsByProviderRole(rc domain.ResourceConfig, grants []*domain.Grant) (reducedGrants []*domain.Grant) {
	grantsGroupedByPermission := map[string]*domain.Grant{}
	var allGrantPermissions []string
	for _, g := range grants {
		// TODO: validate if permissions is empty
		allGrantPermissions = append(allGrantPermissions, g.Permissions[0])
		grantsGroupedByPermission[g.Permissions[0]] = g
	}
	sort.Strings(allGrantPermissions)

	// prioritize roles with more permissions
	sort.Slice(rc.Roles, func(i, j int) bool {
		return len(rc.Roles[i].Permissions) > len(rc.Roles[j].Permissions)
	})
	for _, role := range rc.Roles {
		rolePermissions := role.GetOrderedPermissions()
		if containing, headIndex := utils.SubsliceExists(allGrantPermissions, rolePermissions); containing {
			sampleGrant := grantsGroupedByPermission[rolePermissions[0]]
			sampleGrant.Role = role.ID
			sampleGrant.Permissions = rolePermissions
			reducedGrants = append(reducedGrants, sampleGrant)

			for _, p := range rolePermissions {
				// delete combined grants
				delete(grantsGroupedByPermission, p)
			}
			allGrantPermissions = append(allGrantPermissions[:headIndex], allGrantPermissions[headIndex+1:]...)
		}
	}

	if len(grantsGroupedByPermission) > 0 {
		// add remaining grants with non-registered provider role
		for _, g := range grantsGroupedByPermission {
			reducedGrants = append(reducedGrants, g)
		}
	}

	return
}

func getGrantIDs(grants []domain.Grant) []string {
	var ids []string
	for _, g := range grants {
		ids = append(ids, g.ID)
	}
	return ids
}

func (s *Service) GetGrantsTotalCount(ctx context.Context, filter domain.ListGrantsFilter) (int64, error) {
	return s.repo.GetGrantsTotalCount(ctx, filter)
}

func (s *Service) ListUserRoles(ctx context.Context, owner string) ([]string, error) {
	if owner == "" {
		return nil, ErrEmptyOwner
	}
	return s.repo.ListUserRoles(ctx, owner)
}

// GrantDriftCheck orchestrates drift detection, remediation, and alerting
// for all managed bot accounts.
// A grant is "drifted" when Guardian records it as active but the provider no longer has the access.
// All findings are sent as a single summary alert to adminTeam.
func (s *Service) GrantDriftCheck(ctx context.Context, req domain.GrantDriftCheckRequest) error {
	drifted, err := s.detectDriftedGrants(ctx, req.BotAccountIDs, req.ProviderTypes)
	if err != nil {
		return fmt.Errorf("detecting drifted grants: %w", err)
	}

	if len(drifted) == 0 {
		s.logger.Info(ctx, "no drifted grants found")
		return nil
	}

	if req.DryRun {
		s.logger.Info(ctx, "drifted grants detected (dry run mode, no remediation will be performed)", "drifted_grants", len(drifted))
		return nil
	}

	issues := s.remediateDriftedGrants(ctx, drifted)

	s.logger.Info(ctx, "grant drift check complete",
		"drifted_grants", len(drifted),
		"issues_found", len(issues),
	)

	if len(issues) == 0 {
		return nil
	}

	if errs := s.alertManager.NotifyDriftCheck(ctx, req.AdminTeam, issues); len(errs) > 0 {
		for _, e := range errs {
			s.logger.Error(ctx, "pagerduty drift notification failed", "error", e)
		}
	}

	return nil
}

// remediateDriftedGrants attempts to recreate each drifted grant in the provider,
// groups the results by team, and returns the issues map ready for alerting.
func (s *Service) remediateDriftedGrants(ctx context.Context, drifted []domain.Grant) []domain.GrantDriftIssue {
	issues := make([]domain.GrantDriftIssue, 0, len(drifted))
	for _, g := range drifted {
		issue := s.remediateDriftedGrant(ctx, g)
		issues = append(issues, issue)
	}
	return issues
}

// remediateDriftedGrant attempts to recreate an active grant to the provider
func (s *Service) remediateDriftedGrant(ctx context.Context, g domain.Grant) domain.GrantDriftIssue {
	issue := domain.GrantDriftIssue{
		AccountID: g.AccountID,
		Grant:     &g,
	}

	if err := s.providerService.GrantAccess(ctx, g); err != nil {
		s.logger.Error(ctx, "drift remediation failed: could not recreate grant in provider",
			"grant_id", g.ID,
			"account_id", g.AccountID,
			"error", err,
		)
		issue.RemediationError = err.Error()
	} else {
		s.logger.Info(ctx, "drift remediation succeeded: grant recreated in provider",
			"grant_id", g.ID,
			"account_id", g.AccountID,
		)
	}

	go func() {
		auditCtx := context.WithoutCancel(ctx)
		auditData := map[string]interface{}{
			"grant_id":   g.ID,
			"account_id": g.AccountID,
		}
		if issue.RemediationError != "" {
			auditData["error"] = issue.RemediationError
		}
		if err := s.auditLogger.Log(auditCtx, AuditKeyDriftRemediaton, auditData); err != nil {
			s.logger.Error(ctx, "failed to record drift remediation audit log", "error", err)
		}
	}()

	return issue
}

// detectDriftedGrants returns active grants (filtered to botAccountIDs and providerTypes)
// that are present in Guardian but no longer present in the provider.
func (s *Service) detectDriftedGrants(ctx context.Context, botAccountIDs []string, providerTypes []string) ([]domain.Grant, error) {
	activeGrants, err := s.prepareActiveGrants(ctx, botAccountIDs, providerTypes)
	if err != nil {
		return nil, fmt.Errorf("preparing active grants: %w", err)
	}
	if len(activeGrants) == 0 {
		s.logger.Info(ctx, "no active grants found for drift check")
		return nil, nil
	}

	providerURNMap := make(map[string]string)
	for _, g := range activeGrants {
		// get the provider urns
		if g.Resource == nil {
			continue
		}
		providerURNMap[g.Resource.ProviderURN] = g.Resource.ProviderURN
	}

	providerURNs := make([]string, 0, len(providerURNMap))
	for _, urn := range providerURNMap {
		providerURNs = append(providerURNs, urn)
	}

	providers, err := s.providerService.Find(ctx, domain.ListProvidersFilter{
		Types: providerTypes,
		URNs:  providerURNs,
	})
	if err != nil {
		return nil, fmt.Errorf("finding providers: %w", err)
	}
	if len(providers) == 0 {
		s.logger.Info(ctx, "no providers found for drift check", "provider_types", providerTypes)
		return nil, nil
	}

	activeGrantsMap := buildActiveGrantsMap(activeGrants)
	for _, provider := range providers {
		// As we confirm access in each provider, matching entries are deleted.
		// What remains at the end are the drifted grants.
		s.reconcileProviderAccess(ctx, provider, activeGrantsMap)
	}

	drifted := collectRemainingGrants(activeGrantsMap)

	s.logger.Info(ctx, "drift detection complete",
		"active_grants_checked", len(activeGrants),
		"drifted_grants_found", len(drifted),
	)
	return drifted, nil
}

func (s *Service) prepareActiveGrants(ctx context.Context, botAccountIDs []string, providerTypes []string) ([]domain.Grant, error) {
	// fetch direct ram bot grants first
	activeGrants, err := s.repo.List(ctx, domain.ListGrantsFilter{
		Statuses:      []string{string(domain.GrantStatusActive)},
		AccountIDs:    botAccountIDs,
		ProviderTypes: providerTypes,
	})
	if err != nil {
		return nil, fmt.Errorf("listing active grants: %w", err)
	}

	// then fetch package grants the bot accounts are part of
	packageActiveGrants, err := s.fetchPackageGrants(ctx, botAccountIDs, providerTypes)
	if err != nil {
		return nil, fmt.Errorf("fetching package grants: %w", err)
	}
	activeGrants = append(activeGrants, packageActiveGrants...)

	return activeGrants, nil
}

// buildActiveGrantsMap indexes active grants as [resourceURN][accountSig][permissionsKey] → *Grant.
// Grants without a resource are skipped.
func buildActiveGrantsMap(grants []domain.Grant) map[string]map[string]map[string]*domain.Grant {
	m := map[string]map[string]map[string]*domain.Grant{}
	for i := range grants {
		g := &grants[i]
		if g.Resource == nil {
			continue
		}
		rURN := g.Resource.URN
		sig := getAccountSignature(g.AccountType, g.AccountID)
		if m[rURN] == nil {
			m[rURN] = map[string]map[string]*domain.Grant{}
		}
		if m[rURN][sig] == nil {
			m[rURN][sig] = map[string]*domain.Grant{}
		}
		m[rURN][sig][g.PermissionsKey()] = g
	}
	return m
}

// reconcileProviderAccess fetches live access from a single provider and removes confirmed
// grants from activeGrantsMap. Errors are logged but never fatal — the provider is skipped.
func (s *Service) reconcileProviderAccess(ctx context.Context, provider *domain.Provider, activeGrantsMap map[string]map[string]map[string]*domain.Grant) {
	// directly fetch resource from the grants, deduplicating by URN
	resourcesByURN := make(map[string]*domain.Resource)
	for rURN := range activeGrantsMap {
		for _, byAccount := range activeGrantsMap[rURN] {
			for _, g := range byAccount {
				if g.Resource != nil && g.Resource.ProviderURN == provider.URN {
					resourcesByURN[rURN] = g.Resource
				}
			}
		}
	}
	resources := make([]*domain.Resource, 0, len(resourcesByURN))
	for _, r := range resourcesByURN {
		resources = append(resources, r)
	}

	resourceAccess, err := s.fetchAccessForProvider(ctx, provider, resources)
	if err != nil {
		s.logger.Error(ctx, "failed to fetch access for provider, skipping", "provider_urn", provider.URN, "error", err)
		return
	}

	resourceConfigs := make(map[string]*domain.ResourceConfig, len(provider.Config.Resources))
	for _, rc := range provider.Config.Resources {
		resourceConfigs[rc.Type] = rc
	}
	resourcesMap := make(map[string]*domain.Resource, len(resources))
	for _, r := range resources {
		resourcesMap[r.URN] = r
	}

	for rURN, entries := range resourceAccess {
		resource, ok := resourcesMap[rURN]
		if !ok {
			continue
		}
		for accountSig, accountEntries := range groupAccessEntriesByAccount(entries) {
			providerGrants := accessEntriesToGrants(accountEntries, *resource)
			if rc, ok := resourceConfigs[resource.Type]; ok {
				providerGrants = reduceGrantsByProviderRole(*rc, providerGrants)
			}
			for _, g := range providerGrants {
				if activeGrantsMap[rURN] != nil && activeGrantsMap[rURN][accountSig] != nil {
					delete(activeGrantsMap[rURN][accountSig], g.PermissionsKey())
				}
			}
		}
	}
}

// accessEntriesToGrants converts access entries to grants for a given resource.
func accessEntriesToGrants(entries []domain.AccessEntry, resource domain.Resource) []*domain.Grant {
	grants := make([]*domain.Grant, 0, len(entries))
	for _, ae := range entries {
		g := ae.ToGrant(resource)
		grants = append(grants, &g)
	}
	return grants
}

// collectRemainingGrants flattens the three-level activeGrantsMap into a slice.
// The remaining entries are grants that were not confirmed by any provider — i.e. drifted.
func collectRemainingGrants(m map[string]map[string]map[string]*domain.Grant) []domain.Grant {
	var drifted []domain.Grant
	for _, byAccount := range m {
		for _, byPerm := range byAccount {
			for _, g := range byPerm {
				drifted = append(drifted, *g)
			}
		}
	}
	return drifted
}

func (s *Service) fetchPackageGrants(ctx context.Context, botAccountIDs []string, providerTypes []string) ([]domain.Grant, error) {
	// fetch all active package membership of specified bot accounts.
	packageMembershipGrants, err := s.repo.List(ctx, domain.ListGrantsFilter{
		Statuses:      []string{string(domain.GrantStatusActive)},
		AccountIDs:    botAccountIDs,
		ProviderTypes: []string{guardianProviderType},
		GroupTypes:    []string{guardianGroupTypePackageUser},
	})
	if err != nil {
		return nil, fmt.Errorf("listing active package grants: %w", err)
	}
	if len(packageMembershipGrants) == 0 {
		s.logger.Info(ctx, "no active package grants found for drift check")
		return nil, nil
	}

	// for each package membership, fetch all the active grants
	groupIDMap := make(map[string]string)
	for _, pg := range packageMembershipGrants {
		if pg.Resource == nil {
			continue
		}
		groupIDMap[pg.Resource.ID] = pg.GroupID
	}
	groupIDs := make([]string, 0, len(groupIDMap))
	for groupID := range groupIDMap {
		groupIDs = append(groupIDs, groupID)
	}

	botAccessPackageGrants, err := s.repo.List(ctx, domain.ListGrantsFilter{
		Statuses:      []string{string(domain.GrantStatusActive)},
		ProviderTypes: providerTypes,
		GroupIDs:      groupIDs,
		GroupTypes:    []string{guardianGroupTypePackageAccessBotRAMRole},
	})
	if err != nil {
		return nil, fmt.Errorf("listing package access grants: %w", err)
	}
	if len(botAccessPackageGrants) == 0 {
		return nil, nil
	}

	return botAccessPackageGrants, nil
}

// fetchAccessForProvider calls ListAccess for the given provider and resources.
// Returns nil, false on error (error is logged).
func (s *Service) fetchAccessForProvider(ctx context.Context, provider *domain.Provider, resources []*domain.Resource) (domain.MapResourceAccess, error) {
	access, err := s.providerService.ListAccess(ctx, *provider, resources)
	if err != nil {
		s.logger.Error(ctx, "failed to fetch access from provider, skipping", "provider_urn", provider.URN, "error", err)
		return nil, err
	}
	return access, nil
}
