package oss

import (
	"context"
	"encoding/json"
	"fmt"
	"slices"
	"strings"
	"sync"

	openapi "github.com/alibabacloud-go/darabonba-openapi/client"
	openapiv2 "github.com/alibabacloud-go/darabonba-openapi/v2/client"
	sts "github.com/alibabacloud-go/sts-20150401/client"
	pv "github.com/goto/guardian/core/provider"
	"github.com/goto/guardian/domain"
	"github.com/goto/guardian/utils"

	"github.com/aliyun/aliyun-oss-go-sdk/oss"
)

//go:generate mockery --name=encryptor --exported --with-expecter
type encryptor interface {
	domain.Crypto
}

type PolicyStatement struct {
	Action    []string `json:"Action"`
	Effect    string   `json:"Effect"`
	Principal []string `json:"Principal"`
	Resource  []string `json:"Resource"`
}

type Policy struct {
	Version   string            `json:"Version"`
	Statement []PolicyStatement `json:"Statement"`
}

type provider struct {
	pv.UnimplementedClient
	pv.PermissionManager
	typeName  string
	encryptor encryptor

	ossClients map[string]*oss.Client

	mu sync.Mutex
}

func NewProvider(typeName string, encryptor encryptor) *provider {
	return &provider{
		typeName:   typeName,
		encryptor:  encryptor,
		ossClients: make(map[string]*oss.Client),
	}
}

func (p *provider) GetType() string {
	return p.typeName
}

func (p *provider) GetAccountTypes() []string {
	return []string{AccountTypeRAMUser, AccountTypeRAMRole}
}

func (p *provider) GetRoles(pc *domain.ProviderConfig, resourceType string) ([]*domain.Role, error) {
	return pv.GetRoles(pc, resourceType)
}

func (p *provider) CreateConfig(pc *domain.ProviderConfig) error {
	c := NewConfig(pc, p.encryptor)

	ctx := context.TODO()
	if err := c.ParseAndValidate(); err != nil {
		return err
	}

	return c.EncryptCredentials(ctx)
}

func (p *provider) GetResources(ctx context.Context, pc *domain.ProviderConfig) ([]*domain.Resource, error) {
	client, err := p.getOSSClient(pc, "")
	if err != nil {
		return nil, err
	}

	resources := make([]*domain.Resource, 0)
	availableResourceTypes := pc.GetResourceTypes()

	marker := ""
	for {
		listBucketsResp, err := client.ListBuckets(oss.Marker(marker))
		if err != nil {
			return nil, fmt.Errorf("failed to list buckets: %w", err)
		}

		// TODO: check if owner id is account id
		accountID := listBucketsResp.Owner.ID

		// By default, a maximum of 100 buckets are listed at a time.
		for _, bucket := range listBucketsResp.Buckets {
			if slices.Contains(availableResourceTypes, resourceTypeBucket) {
				resources = append(resources, &domain.Resource{
					ProviderType: pc.Type,
					ProviderURN:  pc.URN,
					Type:         resourceTypeBucket,
					URN:          bucket.Name,
					Name:         bucket.Name,
					GlobalURN:    utils.GetGlobalURN("oss", accountID, resourceTypeBucket, bucket.Name),
				})
			}
		}

		if !listBucketsResp.IsTruncated {
			break
		}
		marker = listBucketsResp.NextMarker
	}

	return resources, nil
}

func (p *provider) GrantAccess(ctx context.Context, pc *domain.ProviderConfig, g domain.Grant) error {
	if g.Resource.Type != resourceTypeBucket {
		return fmt.Errorf("unsupported resource type: %s", g.Resource.Type)
	}

	if len(g.Permissions) > 0 {
		ramRole, err := getRAMRole(g)
		if err != nil {
			return err
		}

		client, err := p.getOSSClient(pc, ramRole)
		if err != nil {
			return err
		}

		existingPolicy, err := client.GetBucketPolicy(g.Resource.URN)
		if err != nil {
			return fmt.Errorf("failed to get bucket Policy: %w", err)
		}

		updatedPolicy, err := updatePolicyToGrantPermissions(existingPolicy, g)
		if err != nil {
			return err
		}

		err = client.SetBucketPolicy(g.Resource.URN, updatedPolicy)
		if err != nil {
			return fmt.Errorf("failed to set bucket policy: %w", err)
		}
	}

	return nil
}

func (p *provider) RevokeAccess(ctx context.Context, pc *domain.ProviderConfig, g domain.Grant) error {
	if g.Resource.Type != resourceTypeBucket {
		return fmt.Errorf("unsupported resource type: %s", g.Resource.Type)
	}

	if len(g.Permissions) > 0 {
		ramRole, err := getRAMRole(g)
		if err != nil {
			return err
		}

		client, err := p.getOSSClient(pc, ramRole)
		if err != nil {
			return err
		}

		existingPolicy, err := client.GetBucketPolicy(g.Resource.URN)
		if err != nil {
			return fmt.Errorf("failed to get bucket Policy: %w", err)
		}

		updatedPolicy, err := updatePolicyToRevokePermissions(existingPolicy, g)
		if err != nil {
			return err
		}

		if updatedPolicy == "" {
			err := client.DeleteBucketPolicy(g.Resource.URN)
			if err != nil {
				return fmt.Errorf("failed to delete bucket policy: %w", err)
			}
		}

		err = client.SetBucketPolicy(g.Resource.URN, updatedPolicy)
		if err != nil {
			return fmt.Errorf("failed to set bucket policy: %w", err)
		}
	}

	return nil
}

func updatePolicyToRevokePermissions(policy string, g domain.Grant) (string, error) {
	var updatedPolicy Policy

	if err := json.Unmarshal([]byte(policy), &updatedPolicy); err != nil {
		return "", fmt.Errorf("failed to unmarshal existing policy: %w", err)
	}

	prinicipalAccountID := g.AccountID
	resourceAccountID, err := getAccountIDFromResource(g.Resource)
	if err != nil {
		return "", err
	}

	var statementToUpdate PolicyStatement
	var updatedStatements []PolicyStatement

	for _, statement := range updatedPolicy.Statement {
		foundStatementToUpdate := false
		if slices.Contains(statement.Principal, prinicipalAccountID) && slices.Contains(statement.Resource, fmt.Sprintf("acs:oss:*:%s:%s", resourceAccountID, g.Resource.URN)) {
			statementToUpdate = statement
			foundStatementToUpdate = true
		}

		if !foundStatementToUpdate {
			updatedStatements = append(updatedStatements, statement)
		}
	}

	// no statement found to update or delete
	if len(updatedStatements) == len(updatedPolicy.Statement) {
		return policy, nil
	}

	var updatedActions []string
	for _, action := range statementToUpdate.Action {
		if !slices.Contains(g.Permissions, action) {
			updatedActions = append(updatedActions, action)
		}
	}

	if len(updatedActions) > 0 {
		statementToUpdate.Action = updatedActions
		updatedStatements = append(updatedStatements, statementToUpdate)
	}

	updatedPolicy.Statement = updatedStatements

	updatedPolicyBytes, err := json.Marshal(updatedPolicy)
	if err != nil {
		return "", fmt.Errorf("failed to marshal updated policy: %w", err)
	}

	return string(updatedPolicyBytes), nil
}

func updatePolicyToGrantPermissions(policy string, g domain.Grant) (string, error) {
	var updatedPolicy Policy
	if err := json.Unmarshal([]byte(policy), &updatedPolicy); err != nil {
		return "", fmt.Errorf("failed to unmarshal existing policy: %w", err)
	}

	prinicpalAccountID := g.AccountID
	resourceAccountID, err := getAccountIDFromResource(g.Resource)
	if err != nil {
		return "", err
	}

	policyGotUpdated := false
	updatedStatements := make([]PolicyStatement, 0)
	for _, statement := range updatedPolicy.Statement {
		if slices.Contains(statement.Principal, prinicpalAccountID) && slices.Contains(statement.Resource, fmt.Sprintf("acs:oss:*:%s:%s", resourceAccountID, g.Resource.URN)) {
			actions := statement.Action
			for _, permission := range g.Permissions {
				if !slices.Contains(actions, permission) {
					actions = append(actions, permission)
				}
			}
			policyGotUpdated = true
			statement.Action = actions
		}
		updatedStatements = append(updatedStatements, statement)
	}

	updatedPolicy.Statement = updatedStatements

	if !policyGotUpdated {
		statement := PolicyStatement{
			Action:    g.Permissions,
			Effect:    "Allow",
			Principal: []string{prinicpalAccountID},
			Resource:  []string{fmt.Sprintf("acs:oss:*:%s:%s", resourceAccountID, g.Resource.URN)},
		}

		updatedPolicy.Statement = append(updatedPolicy.Statement, statement)
	}

	updatedPolicyBytes, err := json.Marshal(updatedPolicy)
	if err != nil {
		return "", fmt.Errorf("failed to marshal updated policy: %w", err)
	}

	return string(updatedPolicyBytes), nil
}

func getClientConfig(providerURN, accountID, accountSecret, regionID, assumeAsRAMRole string) (*openapiv2.Config, error) {
	configV2 := &openapiv2.Config{
		AccessKeyId:     &accountID,
		AccessKeySecret: &accountSecret,
	}

	if assumeAsRAMRole != "" {
		stsEndpoint := fmt.Sprintf("sts.%s.aliyuncs.com", regionID)
		configV1 := &openapi.Config{
			AccessKeyId:     configV2.AccessKeyId,
			AccessKeySecret: configV2.AccessKeySecret,
			Endpoint:        &stsEndpoint,
		}
		stsClient, err := sts.NewClient(configV1)
		if err != nil {
			return nil, fmt.Errorf("failed to initialize STS client: %w", err)
		}
		res, err := stsClient.AssumeRole(&sts.AssumeRoleRequest{
			RoleArn:         &assumeAsRAMRole,
			RoleSessionName: &providerURN,
		})
		if err != nil {
			return nil, fmt.Errorf("failed to assume role %q: %w", assumeAsRAMRole, err)
		}

		// TODO: handle refreshing token when the used one is expired
		configV2.AccessKeyId = res.Body.Credentials.AccessKeyId
		configV2.AccessKeySecret = res.Body.Credentials.AccessKeySecret
		configV2.SecurityToken = res.Body.Credentials.SecurityToken
	}

	return configV2, nil
}

func (p *provider) getCreds(pc *domain.ProviderConfig) (*Credentials, error) {
	cfg := &config{pc, p.encryptor}
	creds, err := cfg.getCredentials()
	if err != nil {
		return nil, err
	}
	if err := creds.decrypt(p.encryptor); err != nil {
		return nil, fmt.Errorf("failed to decrypt credentials: %w", err)
	}
	return creds, nil
}

func (p *provider) getOSSClient(pc *domain.ProviderConfig, ramRole string) (*oss.Client, error) {
	if client, ok := p.ossClients[ramRole]; ok {
		return client, nil
	}

	creds, err := p.getCreds(pc)
	if err != nil {
		return nil, err
	}

	if ramRole == "" {
		ramRole = creds.RAMRole
	}

	clientConfig, err := getClientConfig(pc.URN, creds.AccessKeyID, creds.AccessKeySecret, creds.RegionID, ramRole)
	if err != nil {
		return nil, err
	}

	clientOpts := oss.SecurityToken(*clientConfig.SecurityToken)
	endpoint := fmt.Sprintf("https://oss-%s.aliyuncs.com", creds.RegionID)
	client, err := oss.New(endpoint, *clientConfig.AccessKeyId, *clientConfig.AccessKeySecret, clientOpts)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize oss client: %w", err)
	}

	p.mu.Lock()
	p.ossClients[ramRole] = client
	p.mu.Unlock()
	return client, nil
}

func getRAMRole(g domain.Grant) (string, error) {
	resourceAccountID, err := getAccountIDFromResource(g.Resource)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("acs:ram::%s:role/guardian.bot", resourceAccountID), nil
}

func getAccountIDFromResource(resource *domain.Resource) (string, error) {
	urnParts := strings.Split(resource.GlobalURN, ":")
	if len(urnParts) < 3 {
		return "", fmt.Errorf("invalid GlobalURN format")
	}
	return urnParts[2], nil
}
