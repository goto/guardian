package oss

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"sync"

	pv "github.com/goto/guardian/core/provider"
	"github.com/goto/guardian/domain"
	"github.com/goto/guardian/pkg/aliclientmanager"
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
	mu        *sync.Mutex

	ossClientsCache map[string]*aliclientmanager.Manager[*oss.Client]
}

func NewProvider(typeName string, encryptor encryptor) *provider {
	return &provider{
		typeName:        typeName,
		encryptor:       encryptor,
		mu:              &sync.Mutex{},
		ossClientsCache: make(map[string]*aliclientmanager.Manager[*oss.Client]),
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

	if len(g.Permissions) == 0 {
		return fmt.Errorf("no permissions in grant")
	}

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
		var ossErr oss.ServiceError
		if errors.As(err, &ossErr) && ossErr.StatusCode == http.StatusNotFound {
			existingPolicy = `{"Version":"1","Statement":[]}`
		} else {
			return fmt.Errorf("failed to get bucket Policy: %w", err)
		}
	}

	bucketPolicy, err := updatePolicyToGrantPermissions(existingPolicy, g)
	if err != nil {
		if errors.Is(err, pv.ErrGrantAlreadyExists) {
			return nil
		}
		return err
	}

	err = client.SetBucketPolicy(g.Resource.URN, bucketPolicy)
	if err != nil {
		return fmt.Errorf("failed to set bucket policy: %w", err)
	}

	return nil
}

func (p *provider) RevokeAccess(ctx context.Context, pc *domain.ProviderConfig, g domain.Grant) error {
	if g.Resource.Type != resourceTypeBucket {
		return fmt.Errorf("unsupported resource type: %s", g.Resource.Type)
	}

	if len(g.Permissions) == 0 {
		return nil
	}

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
		var ossErr oss.ServiceError
		if errors.As(err, &ossErr) && ossErr.StatusCode == http.StatusNotFound {
			return fmt.Errorf("access not found for role: %s", g.Role)
		} else {
			return fmt.Errorf("failed to get bucket Policy: %w", err)
		}
	}

	bucketPolicy, err := revokePermissionsFromPolicy(existingPolicy, g)
	if err != nil {
		return err
	}

	if bucketPolicy == "" {
		err = client.DeleteBucketPolicy(g.Resource.URN)
		if err != nil {
			return fmt.Errorf("failed to delete bucket policy: %w", err)
		}
		return nil
	}

	err = client.SetBucketPolicy(g.Resource.URN, bucketPolicy)
	if err != nil {
		return fmt.Errorf("failed to set bucket policy: %w", err)
	}

	return nil
}

func policyStatementExist(statement PolicyStatement, resourceAccountID string, g domain.Grant) bool {
	resourceMatch := slices.Contains(statement.Resource, fmt.Sprintf("acs:oss:*:%s:%s", resourceAccountID, g.Resource.URN))
	if !resourceMatch {
		return false
	}

	if len(statement.Action) != len(g.Permissions) {
		return false
	}

	for _, action := range statement.Action {
		if !slices.Contains(g.Permissions, action) {
			return false
		}
	}
	return true
}

func removePrincipalFromPolicy(statement PolicyStatement, principalAccountID string) PolicyStatement {
	var updatedPrincipals []string
	for _, principal := range statement.Principal {
		if principal == principalAccountID {
			continue
		}

		updatedPrincipals = append(updatedPrincipals, principal)
	}

	statement.Principal = updatedPrincipals
	return statement
}

func revokePermissionsFromPolicy(policyString string, g domain.Grant) (string, error) {
	bucketPolicy, err := unmarshalPolicy(policyString)
	if err != nil {
		return "", err
	}

	principalAccountID, err := getPrincipalFromAccountID(g.AccountID, g.AccountType)
	if err != nil {
		return "", err
	}
	resourceAccountID, err := getAccountIDFromResource(g.Resource)
	if err != nil {
		return "", err
	}

	statements, matchingStatements := findStatementsWithMatchingActions(bucketPolicy, resourceAccountID, g)
	if len(matchingStatements) == 0 {
		return policyString, nil
	}

	statementFoundToRevokePermission := false
	for _, statement := range matchingStatements {
		if !slices.Contains(statement.Principal, principalAccountID) {
			statements = append(statements, statement)
			continue
		}

		// revoke access of the principal
		updatedStatement := removePrincipalFromPolicy(statement, principalAccountID)
		if len(updatedStatement.Principal) > 0 {
			statements = append(statements, updatedStatement)
		}
		statementFoundToRevokePermission = true
	}

	if !statementFoundToRevokePermission {
		return "", fmt.Errorf("access not found for role: %s", g.Role)
	}

	bucketPolicy.Statement = statements
	if len(bucketPolicy.Statement) == 0 {
		return "", nil
	}

	marshaledPolicy, err := marshalPolicy(bucketPolicy)
	if err != nil {
		return "", err
	}

	return marshaledPolicy, nil
}

func updatePolicyToGrantPermissions(policy string, g domain.Grant) (string, error) {
	bucketPolicy, err := unmarshalPolicy(policy)
	if err != nil {
		return "", err
	}

	principalAccountID, err := getPrincipalFromAccountID(g.AccountID, g.AccountType)
	if err != nil {
		return "", err
	}

	resourceAccountID, err := getAccountIDFromResource(g.Resource)
	if err != nil {
		return "", err
	}

	statements, matchingStatements := findStatementsWithMatchingActions(bucketPolicy, resourceAccountID, g)

	resource := fmt.Sprintf("acs:oss:*:%s:%s", resourceAccountID, g.Resource.URN)
	resourceWithWildcard := fmt.Sprintf("acs:oss:*:%s:%s/*", resourceAccountID, g.Resource.URN)
	resources := []string{resourceWithWildcard, resource}

	statementToUpdate := PolicyStatement{
		Action:    g.Permissions,
		Effect:    "Allow",
		Principal: []string{principalAccountID},
		Resource:  resources,
	}

	foundStatementToUpdate := false
	for _, statement := range matchingStatements {
		if slices.Contains(statement.Principal, principalAccountID) {
			return "", pv.ErrGrantAlreadyExists
		}

		if !foundStatementToUpdate {
			foundStatementToUpdate = true
			statement.Principal = append(statement.Principal, principalAccountID)
		}

		statements = append(statements, statement)
	}

	// if no matching statement found, add the new statement
	if !foundStatementToUpdate {
		statements = append(statements, statementToUpdate)
	}

	bucketPolicy.Statement = statements
	marshaledPolicy, err := marshalPolicy(bucketPolicy)
	if err != nil {
		return "", err
	}

	return marshaledPolicy, nil
}

func findStatementsWithMatchingActions(bucketPolicy Policy, resourceAccountID string, g domain.Grant) ([]PolicyStatement, []PolicyStatement) {
	var statements []PolicyStatement
	var matchingStatements []PolicyStatement
	for _, statement := range bucketPolicy.Statement {
		if policyStatementExist(statement, resourceAccountID, g) {
			matchingStatements = append(matchingStatements, statement)
		} else {
			statements = append(statements, statement)
		}
	}
	return statements, matchingStatements
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

func (p *provider) getClientCredentials(pc *domain.ProviderConfig, overrideRamRole string) (string, aliclientmanager.Credentials, error) {
	creds, err := p.getCreds(pc)
	if err != nil {
		return "", aliclientmanager.Credentials{}, err
	}
	ramRole := overrideRamRole
	if creds.RAMRole != "" {
		ramRole = creds.RAMRole
	}
	cacheKeyFrags := fmt.Sprintf("%s:%s:%s", creds.AccessKeyID, creds.RegionID, ramRole)
	manCreds := aliclientmanager.Credentials{
		AccessKeyId:     creds.AccessKeyID,
		AccessKeySecret: creds.AccessKeySecret,
		RegionId:        creds.RegionID,
		RAMRoleARN:      ramRole,
	}
	return cacheKeyFrags, manCreds, nil
}

func (p *provider) getOSSClient(pc *domain.ProviderConfig, overrideRamRole string) (*oss.Client, error) {
	cacheKeyFrags, manCreds, err := p.getClientCredentials(pc, overrideRamRole)
	if err != nil {
		return nil, err
	}

	if c, exists := p.ossClientsCache[cacheKeyFrags]; exists {
		ossClient, err := c.GetClient()
		if err != nil {
			return nil, err
		}
		return ossClient, nil
	}

	clientInitFunc := func(c aliclientmanager.Credentials) (*oss.Client, error) {
		endpoint := fmt.Sprintf("https://oss-%s.aliyuncs.com", c.RegionId)
		return oss.New(endpoint, c.AccessKeyId, c.AccessKeySecret, oss.SecurityToken(c.SecurityToken))
	}

	manager, err := aliclientmanager.NewConfig[*oss.Client](manCreds, clientInitFunc)
	if err != nil {
		return nil, err
	}

	p.mu.Lock()
	p.ossClientsCache[cacheKeyFrags] = manager
	p.mu.Unlock()

	return p.getOSSClient(pc, overrideRamRole)
}

func getRAMRole(g domain.Grant) (string, error) {
	resourceAccountID, err := getAccountIDFromResource(g.Resource)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("acs:ram::%s:role/guardian-bot", resourceAccountID), nil
}

func getAccountIDFromResource(resource *domain.Resource) (string, error) {
	urnParts := strings.Split(resource.GlobalURN, ":")
	if len(urnParts) < 3 {
		return "", fmt.Errorf("invalid GlobalURN format")
	}
	return urnParts[2], nil
}

func getPrincipalFromAccountID(accountID, accountType string) (string, error) {
	// AccountTypeRAMUser = RAM$<uid>:<sub-account-id>
	// AccountTypeRAMRole = acs:ram::<uid>:role/<role-name>
	if accountType == AccountTypeRAMUser {
		accountIDParts := strings.Split(accountID, "$")
		if len(accountIDParts) < 2 {
			return "", fmt.Errorf("invalid accountID format: %q", accountID)
		}

		subParts := strings.Split(accountIDParts[1], ":")
		if len(subParts) < 2 {
			return "", fmt.Errorf("invalid accountID format: %q", accountID)
		}

		return subParts[1], nil
	} else if accountType == AccountTypeRAMRole {
		accountIDParts := strings.Split(accountID, ":")
		if len(accountIDParts) < 5 {
			return "", fmt.Errorf("invalid accountID format: %q", accountID)
		}

		mainAccountID := accountIDParts[3]
		roleNameParts := strings.Split(accountIDParts[4], "/")
		if len(roleNameParts) < 2 {
			return "", fmt.Errorf("invalid accountID format: %q", accountID)
		}

		roleName := roleNameParts[1]

		// STS ARN - arn:sts::<uid>:assumed-role/<role-name>/*
		return fmt.Sprintf("arn:sts::%s:assumed-role/%s/*", mainAccountID, roleName), nil
	}

	return "", fmt.Errorf("invalid account type: %q", accountType)
}

func unmarshalPolicy(policy string) (Policy, error) {
	var bucketPolicy Policy
	if err := json.Unmarshal([]byte(policy), &bucketPolicy); err != nil {
		return Policy{}, fmt.Errorf("failed to unmarshal existing policy: %w", err)
	}
	return bucketPolicy, nil
}

func marshalPolicy(policy Policy) (string, error) {
	if len(policy.Statement) == 0 {
		policy.Statement = make([]PolicyStatement, 0)
	}

	bucketPolicyBytes, err := json.Marshal(policy)
	if err != nil {
		return "", fmt.Errorf("failed to marshal updated policy: %w", err)
	}
	return string(bucketPolicyBytes), nil
}
