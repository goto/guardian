package gate

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strconv"
	"sync"

	pv "github.com/goto/guardian/core/provider"
	"github.com/goto/guardian/domain"
	"github.com/goto/guardian/pkg/gate"
	"github.com/goto/guardian/utils"
	"github.com/mitchellh/mapstructure"
)

const GroupResourceType = "group"

type credentials struct {
	Host   string `mapstructure:"host" yaml:"host" json:"host"`
	APIKey string `mapstructure:"api_key" yaml:"api_key" json:"api_key"`
}

func (c credentials) validate() error {
	if c.Host == "" {
		return errors.New("host is required")
	}
	if c.APIKey == "" {
		return errors.New("api_key is required")
	}
	return nil
}

func (c *credentials) encrypt(encryptor domain.Encryptor) error {
	encryptedAPIKey, err := encryptor.Encrypt(c.APIKey)
	if err != nil {
		return err
	}

	c.APIKey = encryptedAPIKey
	return nil
}

func (c *credentials) decrypt(decryptor domain.Decryptor) error {
	decryptedAPIKey, err := decryptor.Decrypt(c.APIKey)
	if err != nil {
		return err
	}

	c.APIKey = decryptedAPIKey
	return nil
}

type config struct {
	*domain.ProviderConfig
}

func (c *config) validate() error {
	// validate credentials
	if c.Credentials == nil {
		return fmt.Errorf("missing credentials")
	}
	creds, err := c.getCredentials()
	if err != nil {
		return err
	}
	if err := creds.validate(); err != nil {
		return fmt.Errorf("invalid credentials: %w", err)
	}

	// validate resource config
	for _, rc := range c.Resources {
		if rc.Type != "group" {
			return fmt.Errorf("invalid resource type: %q", rc.Type)
		}

		for _, role := range rc.Roles {
			for _, permission := range role.Permissions {
				permissionString, ok := permission.(string)
				if !ok {
					return fmt.Errorf("unexpected permission type: %T, expected: string", permission)
				}
				if permissionString != "member" {
					return fmt.Errorf("invalid permission: %q", permissionString)
				}
			}
		}
	}

	return nil
}

func (c *config) getCredentials() (*credentials, error) {
	if creds, ok := c.Credentials.(credentials); ok { // parsed
		return &creds, nil
	} else if mapCreds, ok := c.Credentials.(map[string]interface{}); ok { // not parsed
		var creds credentials
		if err := mapstructure.Decode(mapCreds, &creds); err != nil {
			return nil, fmt.Errorf("unable to decode credentials: %w", err)
		}
		return &creds, nil
	}

	return nil, fmt.Errorf("invalid credentials type: %T", c.Credentials)
}

type provider struct {
	pv.UnimplementedClient
	pv.PermissionManager

	typeName string
	clients  map[string]*gate.Client
	crypto   domain.Crypto

	mutex sync.Mutex
}

func NewProvider(typeName string, crypto domain.Crypto) *provider {
	return &provider{
		typeName: typeName,
		clients:  map[string]*gate.Client{},
		crypto:   crypto,
		mutex:    sync.Mutex{},
	}
}

func (p *provider) GetType() string {
	return p.typeName
}

func (p *provider) CreateConfig(pc *domain.ProviderConfig) error {
	cfg := &config{pc}
	if err := cfg.validate(); err != nil {
		return fmt.Errorf("invalid gate config: %w", err)
	}

	// encrypt sensitive config
	creds, err := cfg.getCredentials()
	if err != nil {
		return err
	}
	if err := creds.encrypt(p.crypto); err != nil {
		return fmt.Errorf("unable to encrypt credentials: %w", err)
	}
	pc.Credentials = creds

	return nil
}

func (p *provider) GetResources(ctx context.Context, pc *domain.ProviderConfig) ([]*domain.Resource, error) {
	client, err := p.getClient(pc)
	if err != nil {
		return nil, err
	}

	if !slices.Contains(pc.GetResourceTypes(), GroupResourceType) {
		return nil, nil
	}

	resources := []*domain.Resource{}
	page := 1
	for {
		groups, res, err := client.ListGroups(ctx, &gate.ListGroupsRequest{Page: page})
		if err != nil {
			return nil, err
		}
		if res.StatusCode != http.StatusOK {
			return nil, fmt.Errorf("failed to list groups: %s", res.Status)
		}

		if len(groups) == 0 {
			break
		}
		page += 1

		for _, group := range groups {
			groupID := strconv.Itoa(group.ID)
			resources = append(resources, &domain.Resource{
				ProviderType: pc.Type,
				ProviderURN:  pc.URN,
				Type:         GroupResourceType,
				URN:          groupID,
				Name:         group.Name,
				GlobalURN:    utils.GetGlobalURN(pc.Type, pc.URN, GroupResourceType, groupID),
			})
		}
	}

	return resources, nil
}

func (p *provider) GrantAccess(ctx context.Context, pc *domain.ProviderConfig, g domain.Grant) error {
	client, err := p.getClient(pc)
	if err != nil {
		return err
	}

	groupID, err := strconv.Atoi(g.Resource.URN)
	if err != nil {
		return fmt.Errorf("invalid group ID: %q: %w", g.Resource.URN, err)
	}

	userID, err := strconv.Atoi(g.AccountID)
	if err != nil {
		return fmt.Errorf("invalid user ID: %q: %w", g.AccountID, err)
	}

	switch g.Resource.Type {
	case GroupResourceType:
		res, err := client.AddUserToGroup(ctx, groupID, userID)
		if err != nil {
			return fmt.Errorf("failed to add user %q to gate group %q: %w", g.AccountID, g.Resource.URN, err)
		}
		if res.StatusCode != http.StatusNoContent {
			return fmt.Errorf("failed to add user %q to gate group %q: %s", g.AccountID, g.Resource.URN, res.Status)
		}
	default:
		return fmt.Errorf("unexpected resource type: %q", g.Resource.Type)
	}

	return nil
}

func (p *provider) RevokeAccess(ctx context.Context, pc *domain.ProviderConfig, g domain.Grant) error {
	client, err := p.getClient(pc)
	if err != nil {
		return err
	}

	groupID, err := strconv.Atoi(g.Resource.URN)
	if err != nil {
		return fmt.Errorf("invalid group ID: %q: %w", g.Resource.URN, err)
	}

	userID, err := strconv.Atoi(g.AccountID)
	if err != nil {
		return fmt.Errorf("invalid user ID: %q: %w", g.AccountID, err)
	}

	switch g.Resource.Type {
	case GroupResourceType:
		res, err := client.RemoveUserFromGroup(ctx, groupID, userID)
		if err != nil {
			return fmt.Errorf("failed to remove user %q from gate group %q: %w", g.AccountID, g.Resource.URN, err)
		}
		if res.StatusCode != http.StatusNoContent {
			return fmt.Errorf("failed to remove user %q from gate group %q: %s", g.AccountID, g.Resource.URN, res.Status)
		}
	default:
		return fmt.Errorf("unexpected resource type: %q", g.Resource.Type)
	}

	return nil
}

func (p *provider) GetRoles(pc *domain.ProviderConfig, resourceType string) ([]*domain.Role, error) {
	return pv.GetRoles(pc, resourceType)
}

func (p *provider) GetAccountTypes() []string {
	return []string{"gate_user_id"}
}

func (p *provider) getClient(pc *domain.ProviderConfig) (*gate.Client, error) {
	if p.clients[pc.URN] != nil {
		return p.clients[pc.URN], nil
	}

	config := &config{pc}
	creds, err := config.getCredentials()
	if err != nil {
		return nil, fmt.Errorf("failed to get credentials: %w", err)
	}
	if err := creds.decrypt(p.crypto); err != nil {
		return nil, fmt.Errorf("failed to decrypt credentials: %w", err)
	}

	opts := []gate.ClientOption{
		gate.WithAPIKey(creds.APIKey),
		gate.WithQueryParamAuthMethod(),
	}

	client, err := gate.NewClient(creds.Host, opts...)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize client: %w", err)
	}

	p.mutex.Lock()
	p.clients[pc.URN] = client
	p.mutex.Unlock()
	return client, nil
}
