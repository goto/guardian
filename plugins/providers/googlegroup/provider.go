package googlegroup

import (
	"context"
	"encoding/base64"
	"fmt"
	"reflect"
	"regexp"
	"slices"
	"strings"

	"sync"

	pv "github.com/goto/guardian/core/provider"
	"github.com/goto/guardian/domain"
	"github.com/goto/guardian/pkg/evaluator"
	"github.com/goto/guardian/pkg/log"
	"github.com/goto/guardian/utils"
	admin "google.golang.org/api/admin/directory/v1"
)

type encryptor interface {
	domain.Crypto
}

type AdminService interface {
	ListGroups(ctx context.Context, customer string, pageToken string) ([]*admin.Group, string, error)
	InsertMember(ctx context.Context, groupKey string, member *admin.Member) (*admin.Member, error)
	RemoveMember(ctx context.Context, groupKey string, memberKey string) error
}

type Provider struct {
	pv.UnimplementedClient
	pv.PermissionManager

	typeName  string
	encryptor encryptor
	logger    log.Logger
	mu        sync.Mutex
	Clients   map[string]AdminService
}

func NewProvider(
	typeName string,
	encryptor encryptor,
	logger log.Logger,
) *Provider {
	return &Provider{
		typeName:  typeName,
		encryptor: encryptor,
		logger:    logger,
		mu:        sync.Mutex{},
		Clients:   make(map[string]AdminService),
	}
}

func (p *Provider) GetType() string {
	return p.typeName
}

func (p *Provider) GetAccountTypes() []string {
	return []string{accountTypeUser, accountTypeGroup, accountTypeServiceAccount}
}

func (p *Provider) GetRoles(pc *domain.ProviderConfig, resourceType string) ([]*domain.Role, error) {
	return pv.GetRoles(pc, resourceType)
}

func (p *Provider) CreateConfig(pc *domain.ProviderConfig) error {
	cfg := &config{
		ProviderConfig: pc,
	}

	if err := cfg.validateConfig(); err != nil {
		return fmt.Errorf("config validation failed: %w", err)
	}

	creds, err := cfg.getCredentials()
	if err != nil {
		return fmt.Errorf("failed to get credentials: %w", err)
	}

	if err := creds.encrypt(p.encryptor); err != nil {
		return err
	}

	pc.Credentials = creds

	return nil
}

func (p *Provider) GetResources(ctx context.Context, pc *domain.ProviderConfig) ([]*domain.Resource, error) {
	client, err := p.GetAdminServiceClient(ctx, *pc)
	if err != nil {
		return nil, fmt.Errorf("failed to get admin service client: %w", err)
	}

	resourceTypes := pc.GetResourceTypes()
	if len(resourceTypes) != 1 || resourceTypes[0] != resourceTypeGroup {
		return nil, fmt.Errorf("%w: %s, %s is the only valid type",
			ErrInvalidResourceType, resourceTypes[0], resourceTypeGroup)
	}

	resourceFilter := pc.GetFilterForResourceType(resourceTypeGroup)
	resources := []*domain.Resource{}
	var pageToken string

	for {
		groups, nextPageToken, err := client.ListGroups(ctx, "my_customer", pageToken)
		if err != nil {
			return nil, fmt.Errorf("failed to list groups: %w", err)
		}

		if groups == nil {
			break
		}

		for _, group := range groups {
			resource := &domain.Resource{
				ProviderType: pc.Type,
				ProviderURN:  pc.URN,
				Type:         resourceTypeGroup,
				URN:          group.Email,
				Name:         group.Name,
				GlobalURN:    utils.GetGlobalURN("googlegroup", pc.URN, resourceTypeGroup, group.Email),
			}

			shouldInclude := true
			if resourceFilter != "" {
				v, err := evaluator.Expression(resourceFilter).EvaluateWithStruct(resource)
				if err != nil {
					p.logger.Error(ctx, fmt.Sprintf("evaluating filter expression %q for group %q: %v", resourceFilter, group.Email, err))
					shouldInclude = false
				} else if reflect.ValueOf(v).IsZero() {
					shouldInclude = false
				} else if !v.(bool) {
					shouldInclude = false
				}
			}
			if shouldInclude {
				resources = append(resources, resource)
			}
		}

		pageToken = nextPageToken
		if pageToken == "" {
			break
		}
	}

	return resources, nil
}

func (p *Provider) GrantAccess(ctx context.Context, pc *domain.ProviderConfig, grant domain.Grant) error {

	memberEmail := grant.AccountID

	// check if the memberEmail matches the expected format for the account type
	if err := p.validateEmailForAccountType(grant.AccountType, memberEmail); err != nil {
		return fmt.Errorf("invalid email format for account type %q: %w", grant.AccountType, err)
	}

	client, err := p.GetAdminServiceClient(ctx, *pc)
	if err != nil {
		return fmt.Errorf("failed to get admin service client: %w", err)
	}

	googleGroupEmail := grant.Resource.URN

	if len(grant.Permissions) != 1 {
		return fmt.Errorf("unexpected number of permissions: %d", len(grant.Permissions))
	}

	if !slices.Contains(validRoles, strings.ToLower(grant.Permissions[0])) {
		return fmt.Errorf("invalid grant permission: %q", grant.Permissions[0])
	}

	if grant.Resource.Type != resourceTypeGroup {
		return fmt.Errorf("invalid resource type: %q", grant.Resource.Type)
	}

	member := &admin.Member{
		Email: memberEmail,
		Role:  strings.ToUpper(grant.Permissions[0]),
	}

	_, err = client.InsertMember(ctx, googleGroupEmail, member)
	if err != nil {
		if strings.Contains(err.Error(), "Member already exists") {
			p.logger.Debug(ctx, fmt.Sprintf("%s member already exists in %s group",
				memberEmail, googleGroupEmail))
			return nil
		}
		return fmt.Errorf("failed to add member: %w", err)
	}

	p.logger.Debug(ctx, fmt.Sprintf("Successfully added %s to %s group", memberEmail, googleGroupEmail))
	return nil
}

func (p *Provider) RevokeAccess(ctx context.Context, pc *domain.ProviderConfig, grant domain.Grant) error {

	client, err := p.GetAdminServiceClient(ctx, *pc)
	if err != nil {
		return fmt.Errorf("failed to get admin client: %w", err)
	}

	userEmail := grant.AccountID
	googleGroupEmail := grant.Resource.URN

	if len(grant.Permissions) != 1 {
		return fmt.Errorf("unexpected number of permissions: %d", len(grant.Permissions))
	}

	if !slices.Contains(validRoles, strings.ToLower(grant.Permissions[0])) {
		return fmt.Errorf("invalid grant permission: %q", grant.Permissions[0])
	}

	if grant.Resource.Type != resourceTypeGroup {
		return fmt.Errorf("invalid resource type: %q", grant.Resource.Type)
	}

	err = client.RemoveMember(ctx, googleGroupEmail, userEmail)
	if err != nil {
		if strings.Contains(err.Error(), "Resource Not Found") {
			p.logger.Debug(ctx, fmt.Sprintf("%s member doesn't exist in %s group", userEmail, googleGroupEmail))
			return nil
		}
		return fmt.Errorf("failed to remove member: %w", err)
	}

	p.logger.Debug(ctx, fmt.Sprintf("Successfully removed %s from %s group", userEmail, googleGroupEmail))
	return nil
}

func (p *Provider) GetAdminServiceClient(ctx context.Context, pc domain.ProviderConfig) (AdminService, error) {
	if client, ok := p.Clients[pc.URN]; ok {
		return client, nil
	}

	cfg := &config{&pc}
	creds, err := cfg.getCredentials()
	if err != nil {
		return nil, err
	}

	if err := creds.decrypt(p.encryptor); err != nil {
		return nil, fmt.Errorf("unable to decrypt credentials: %w", err)
	}

	saKey, err := base64.StdEncoding.DecodeString(creds.ServiceAccountKey)
	if err != nil {
		return nil, fmt.Errorf("failed to decode service account base64 string: %w", err)
	}

	svc, err := newAdminService(ctx, saKey, creds.ImpersonateUserEmail)
	if err != nil {
		return nil, fmt.Errorf("failed to create admin service client: %w", err)
	}

	p.mu.Lock()
	defer p.mu.Unlock()
	p.Clients[pc.URN] = svc
	return svc, nil
}

func (p *Provider) validateEmailForAccountType(accountType, email string) error {
	emailRegex := regexp.MustCompile(emailRegexPattern)
	if !emailRegex.MatchString(email) {
		return fmt.Errorf("invalid email format")
	}

	saRegex := regexp.MustCompile(saRegexPattern)
	switch accountType {
	case accountTypeServiceAccount:
		if !saRegex.MatchString(email) {
			return ErrInvalidServiceAccountEmailFormat
		}
		return nil

	case accountTypeUser:
		if saRegex.MatchString(email) {
			return ErrInvalidUserEmailFormat
		}
		return nil
	case accountTypeGroup:
		return nil

	default:
		return fmt.Errorf("unsupported account type: %s", accountType)
	}
}
