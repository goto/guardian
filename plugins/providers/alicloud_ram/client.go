package alicloud_ram

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"

	openapi "github.com/alibabacloud-go/darabonba-openapi/v2/client"
	ram "github.com/alibabacloud-go/ram-20150501/v2/client"
	ram20150501 "github.com/alibabacloud-go/ram-20150501/v2/client"
	utils "github.com/alibabacloud-go/tea-utils/v2/service"
	"github.com/aliyun/credentials-go/credentials"
	"github.com/bearaujus/bptr"
	"github.com/goto/guardian/domain"
)

const (
	PolicyTypeSystem = "System"
	PolicyTypeCustom = "Custom"

	aliAccountUserIdDomainSuffix = ".onaliyun.com"
	aliAccountUserIdPattern      = `^[a-zA-Z0-9._%+-]+@[0-9]+\.onaliyun\.com$`
	aliRoleSessionExpiration     = 3600

	aliAccountTypeAccessKey  = "access_key"
	aliAccountTypeRamRoleARN = "ram_role_arn"

	STSTrustPolicyRole = "STSTrustPolicy"
)

// getRoleMutex returns (and lazily creates) a mutex for the given role name
func (c *aliCloudRAMClient) getRoleMutex(roleName string) *sync.Mutex {
	mu, _ := c.roleMu.LoadOrStore(roleName, &sync.Mutex{})
	return mu.(*sync.Mutex)
}

// NewAliCloudRAMClient initializes a new instance of AliCloudRAMClient.
//
// This function creates and configures an `aliCloudRAMClient` with the provided credentials
// and resource information. If a role ARN (`ramRole`) is specified, it will
// be included in the configuration for assuming a RAM role. The function also
// validates the configuration by attempting to create a new RAM client instance.
func NewAliCloudRAMClient(accessKeyID, accessKeySecret, ramRole, regionId string) (AliCloudRAMClient, error) {
	c := &aliCloudRAMClient{
		accessKeyId:     accessKeyID,
		accessKeySecret: accessKeySecret,
		ramRole:         ramRole,
		regionId:        regionId,
	}

	// Validate the ram role ARN if present
	if c.ramRole != "" {
		arn, err := parseAliCloudARN(c.ramRole)
		if err != nil {
			return nil, ErrInvalidAliCloudRoleARN
		}
		if arn.Service != "ram" {
			return nil, ErrRoleServiceTypeIsNotSupported
		}
		if arn.ResourceType != "role" {
			return nil, ErrRoleResourceTypeIsNotSupported
		}
		if arn.ResourceName == "" {
			return nil, ErrRoleResourceNameIsEmpty
		}
	}

	// Validate the configuration by creating a new dummy request client
	_, err := c.newRequestClient()
	if err != nil {
		return nil, err
	}

	return c, nil
}

func (c *aliCloudRAMClient) GrantAccess(_ context.Context, policyName, policyType, accountID string) error {
	reqClient, err := c.newRequestClient()
	if err != nil {
		return err
	}

	// TODO: find a way to add parent context to the request
	_, err = reqClient.AttachPolicyToUserWithOptions(&ram.AttachPolicyToUserRequest{
		PolicyName: &policyName,
		PolicyType: &policyType,
		UserName:   &accountID,
	}, &utils.RuntimeOptions{})
	if err != nil {
		// TODO: find the error list on SDK instead of using strings contains
		if strings.Contains(err.Error(), "EntityAlreadyExists.User.Policy") {
			return ErrPermissionAlreadyExists
		}
		return err
	}

	return nil
}

func (c *aliCloudRAMClient) RevokeAccess(_ context.Context, policyName, policyType, accountID string) error {
	reqClient, err := c.newRequestClient()
	if err != nil {
		return err
	}

	// TODO: find a way to add parent context to the request
	_, err = reqClient.DetachPolicyFromUserWithOptions(&ram.DetachPolicyFromUserRequest{
		PolicyName: &policyName,
		PolicyType: &policyType,
		UserName:   &accountID,
	}, &utils.RuntimeOptions{})
	if err != nil {
		// TODO: find the error list on SDK instead of using strings contains
		if strings.Contains(err.Error(), "EntityNotExist.User.Policy") {
			return ErrPermissionNotExist
		}
		return err
	}

	return nil
}

func (c *aliCloudRAMClient) GrantAccessToRole(_ context.Context, policyName, policyType, roleName string) error {
	reqClient, err := c.newRequestClient()
	if err != nil {
		return err
	}

	// TODO: find a way to add parent context to the request
	_, err = reqClient.AttachPolicyToRoleWithOptions(&ram.AttachPolicyToRoleRequest{
		PolicyName: &policyName,
		PolicyType: &policyType,
		RoleName:   &roleName,
	}, &utils.RuntimeOptions{})
	if err != nil {
		// TODO: find the error list on SDK instead of using strings contains
		if strings.Contains(err.Error(), "EntityAlreadyExists.Role.Policy") {
			return ErrPermissionAlreadyExists
		}
		return err
	}

	return nil
}

func (c *aliCloudRAMClient) RevokeAccessFromRole(_ context.Context, policyName, policyType, roleName string) error {
	reqClient, err := c.newRequestClient()
	if err != nil {
		return err
	}

	// TODO: find a way to add parent context to the request
	_, err = reqClient.DetachPolicyFromRoleWithOptions(&ram.DetachPolicyFromRoleRequest{
		PolicyName: &policyName,
		PolicyType: &policyType,
		RoleName:   &roleName,
	}, &utils.RuntimeOptions{})
	if err != nil {
		// TODO: find the error list on SDK instead of using strings contains
		if strings.Contains(err.Error(), "EntityNotExist.Role.Policy") {
			return ErrPermissionNotExist
		}
		return err
	}

	return nil
}

func (c *aliCloudRAMClient) ListAccess(_ context.Context, _ domain.ProviderConfig, _ []*domain.Resource) (domain.MapResourceAccess, error) {
	return nil, ErrUnimplementedMethod // TODO
}

func (c *aliCloudRAMClient) GetAllPoliciesByType(_ context.Context, policyType string, maxItems int32) ([]*ram.ListPoliciesResponseBodyPoliciesPolicy, error) {
	reqClient, err := c.newRequestClient()
	if err != nil {
		return nil, err
	}

	result := make([]*ram.ListPoliciesResponseBodyPoliciesPolicy, 0)
	var marker *string
	for {
		// TODO: find a way to add parent context to the request
		resp, err := reqClient.ListPoliciesWithOptions(&ram.ListPoliciesRequest{
			Marker:     marker,
			MaxItems:   &maxItems,
			PolicyType: &policyType,
		}, &utils.RuntimeOptions{})
		if err != nil {
			return nil, err
		}

		result = append(result, resp.Body.Policies.Policy...)
		if resp.Body.Marker == nil {
			break
		}
		marker = resp.Body.Marker
	}

	return result, nil
}

func (c *aliCloudRAMClient) GetRole(name string) (*Role, string, error) {
	if name == "" {
		return nil, "", fmt.Errorf("role name cannot be empty")
	}

	reqClient, err := c.newRequestClient()
	if err != nil {
		return nil, "", fmt.Errorf("failed to create request client: %w", err)
	}

	// lock is held until after UpdateRole
	getRoleRequest := &ram20150501.GetRoleRequest{
		RoleName: &name,
	}

	// Update Role
	var role *Role
	response, err := reqClient.GetRole(getRoleRequest)
	if err != nil {
		return nil, "", err
	}
	etag := ""
	if val, ok := response.Headers["etag"]; ok && val != nil {
		etag = *val
	}
	if response != nil && response.Body != nil && response.Body.Role != nil {

		role, err = toRAMRole(response.Body.Role)
		if err != nil {
			return nil, "", err
		}
	}

	if role == nil {
		return nil, "", fmt.Errorf("failed to get the role")
	}

	return role, etag, nil
}

func (c *aliCloudRAMClient) UpdateRole(name, description, policy, etag string) (*Role, error) {
	if name == "" {
		return nil, fmt.Errorf("role name cannot be empty")
	}

	reqClient, err := c.newRequestClient()
	if err != nil {
		return nil, fmt.Errorf("failed to create request client: %w", err)
	}
	// initialize the map before writing to it
	if reqClient.Headers == nil {
		reqClient.Headers = make(map[string]*string)
	}
	reqClient.Headers["etag"] = &etag

	// lock is held until after UpdateRole
	updateRoleRequest := &ram20150501.UpdateRoleRequest{
		RoleName:                    &name,
		NewAssumeRolePolicyDocument: &policy,
	}
	if description != "" {
		updateRoleRequest.NewDescription = &description
	}

	// Update Role
	var role *Role
	response, err := reqClient.UpdateRole(updateRoleRequest)
	if err != nil {
		return nil, err
	}

	if response != nil && response.Body != nil && response.Body.Role != nil {
		role, err = toRAMRoleUpdate(response.Body.Role)
		if err != nil {
			return nil, err
		}
	}

	if role == nil {
		return nil, fmt.Errorf("failed to update the role")
	}

	return role, nil
}

func (c *aliCloudRAMClient) GetAllRoles(_ context.Context, maxItems int32) ([]*ram.ListRolesResponseBodyRolesRole, error) {
	reqClient, err := c.newRequestClient()
	if err != nil {
		return nil, err
	}

	result := make([]*ram.ListRolesResponseBodyRolesRole, 0)
	var marker *string
	for {
		resp, err := reqClient.ListRolesWithOptions(&ram.ListRolesRequest{
			Marker:   marker,
			MaxItems: &maxItems,
		}, &utils.RuntimeOptions{})
		if err != nil {
			return nil, err
		}

		result = append(result, resp.Body.Roles.Role...)
		if resp.Body.Marker == nil {
			break
		}
		marker = resp.Body.Marker
	}

	return result, nil
}

func (c *aliCloudRAMClient) GrantRamRoleAccess(_ context.Context, r domain.Resource, account_id, role string) error {
	if role != "STSTrustPolicy" {
		return nil
	}

	mu := c.getRoleMutex(r.Name)
	mu.Lock()
	defer mu.Unlock()

	ramRole, etag, err := c.GetRole(r.Name)
	if err != nil {
		return fmt.Errorf("failed to get RAM role: %w", err)
	}

	updatedRAMPolicy, err := GrantSTSTrustPolicyRole(*ramRole, account_id)
	if err != nil {
		return fmt.Errorf("failed to grant STS trust policy role: %w", err)
	}

	_, err = c.UpdateRole(r.Name, "grant sts access for account "+account_id, updatedRAMPolicy, etag)
	if err != nil {
		return fmt.Errorf("failed to update role: %w", err)
	}

	return nil
}

func (c *aliCloudRAMClient) RevokeRamRoleAccess(_ context.Context, r domain.Resource, account_id, role string) error {
	if role != "STSTrustPolicy" {
		return nil
	}

	mu := c.getRoleMutex(r.Name)
	mu.Lock()
	defer mu.Unlock()

	ramRole, etag, err := c.GetRole(r.Name)
	if err != nil {
		return fmt.Errorf("failed to get RAM role: %w", err)
	}

	updatedRAMPolicy, err := RevokeSTSTrustPolicyRole(*ramRole, account_id)
	if err != nil {
		return fmt.Errorf("failed to revoke STS trust policy role: %w", err)
	}

	_, err = c.UpdateRole(r.Name, "revoke sts access for account "+account_id, updatedRAMPolicy, etag)
	if err != nil {
		return fmt.Errorf("failed to update role: %w", err)
	}

	return nil
}

// newRequestClient creates a new RAM client instance for each request.
//
// AliCloud SDK clients are not concurrency-safe due to their use of a builder pattern
// for sending and receiving requests. To avoid race conditions, we must create a
// new client instance for every request.
//
// The client uses RAM (Resource Access Management) credentials to authenticate with AliCloud.
// By default, it uses access key credentials. If a role ARN (`ramRole`) is specified,
// it assumes that role to generate temporary session credentials.
func (c *aliCloudRAMClient) newRequestClient() (*ram.Client, error) {
	// Default to access key credentials (RAM User)
	credentialConfig := &credentials.Config{
		Type:            bptr.FromStringNilAble(aliAccountTypeAccessKey),
		AccessKeyId:     bptr.FromStringNilAble(c.accessKeyId),
		AccessKeySecret: bptr.FromStringNilAble(c.accessKeySecret),
	}

	// If a role to assume is specified, configure credentials to assume the role (RAM Role)
	if c.ramRole != "" {
		credentialConfig.Type = bptr.FromStringNilAble(aliAccountTypeRamRoleARN)
		credentialConfig.RoleArn = bptr.FromStringNilAble(c.ramRole)
		credentialConfig.RoleSessionExpiration = bptr.FromIntNilAble(aliRoleSessionExpiration)
	}

	credential, err := credentials.NewCredential(credentialConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to create a new credentials: %w", err)
	}

	reqClient, err := ram.NewClient(&openapi.Config{
		Credential: credential,
		RegionId:   bptr.FromStringNilAble(c.regionId),
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create RAM client: %w", err)
	}

	return reqClient, nil
}

type aliCloudARN struct {
	Prefix       string // The ARN prefix (e.g., "acs")
	Service      string // The service name (e.g., "ram")
	Region       string // The region (empty for global services like RAM)
	AccountID    string // The account ID (e.g., "5123xxxxxxx")
	ResourceType string // The resource type (e.g., "role")
	ResourceName string // The resource name (e.g., "role-name")
}

// parseAliCloudARN parses an ARN string into an aliCloudARN struct
// example: `acs:ram::500xxxxxxxx:role/role-name`
func parseAliCloudARN(arn string) (*aliCloudARN, error) {
	// Split the ARN string by ":"
	parts := strings.Split(arn, ":")
	if len(parts) != 5 {
		return nil, errors.New("invalid ARN format")
	}

	// Split the last part to extract resource type and name
	resourceParts := strings.Split(parts[4], "/")
	if len(resourceParts) != 2 {
		return nil, errors.New("invalid resource format")
	}

	return &aliCloudARN{
		Prefix:       parts[0],
		Service:      parts[1],
		Region:       parts[2],
		AccountID:    parts[3],
		ResourceType: resourceParts[0],
		ResourceName: resourceParts[1],
	}, nil
}

func toRAMRole(r *ram20150501.GetRoleResponseBodyRole) (*Role, error) {
	if r == nil {
		return nil, fmt.Errorf("nil ram role provided")
	}

	return &Role{
		Arn:                      r.Arn,
		AssumeRolePolicyDocument: r.AssumeRolePolicyDocument,
		CreateDate:               r.CreateDate,
		Description:              r.Description,
		MaxSessionDuration:       r.MaxSessionDuration,
		RoleID:                   r.RoleId,
		RoleName:                 r.RoleName,
	}, nil
}

func toRAMRoleUpdate(r *ram20150501.UpdateRoleResponseBodyRole) (*Role, error) {
	if r == nil {
		return nil, fmt.Errorf("nil ram role provided")
	}

	return &Role{
		Arn:                      r.Arn,
		AssumeRolePolicyDocument: r.AssumeRolePolicyDocument,
		CreateDate:               r.CreateDate,
		Description:              r.Description,
		MaxSessionDuration:       r.MaxSessionDuration,
		RoleID:                   r.RoleId,
		RoleName:                 r.RoleName,
	}, nil
}

func GrantSTSTrustPolicyRole(role Role, account_id string) (string, error) {
	// Unmarshal the existing policy
	if role.AssumeRolePolicyDocument == nil {
		return "", fmt.Errorf("AssumeRolePolicyDocument is nil")
	}

	var ramPolicy RAMPolicy
	if err := json.Unmarshal([]byte(*role.AssumeRolePolicyDocument), &ramPolicy); err != nil {
		return "", fmt.Errorf("failed to unmarshal existing RAM policy: %w", err)
	}

	// Find the AssumeRole statement and update RAM principal
	for i, stmt := range ramPolicy.Statement {
		if stmt.Action == "sts:AssumeRole" {
			if !slices.Contains(stmt.Principal.RAM, account_id) {
				currStatement := &ramPolicy.Statement[i]
				currStatement.Principal.RAM = append(currStatement.Principal.RAM, account_id)
			}
			break
		}
	}

	ramPolicyBytes, err := json.Marshal(ramPolicy)
	if err != nil {
		return "", fmt.Errorf("failed to marshal RAM policy: %w", err)
	}
	updatedRAMPolicy := string(ramPolicyBytes)
	return updatedRAMPolicy, nil
}

func RevokeSTSTrustPolicyRole(role Role, account_id string) (string, error) {
	// Unmarshal the existing policy
	if role.AssumeRolePolicyDocument == nil {
		return "", fmt.Errorf("AssumeRolePolicyDocument is nil")
	}
	var ramPolicy RAMPolicy
	if err := json.Unmarshal([]byte(*role.AssumeRolePolicyDocument), &ramPolicy); err != nil {
		return "", fmt.Errorf("failed to unmarshal existing RAM policy: %w", err)
	}

	// Find the AssumeRole statement and remove the RAM principal
	for i, stmt := range ramPolicy.Statement {
		if stmt.Action == "sts:AssumeRole" {
			currStatement := &ramPolicy.Statement[i]
			currStatement.Principal.RAM = slices.DeleteFunc(currStatement.Principal.RAM, func(s string) bool {
				return s == account_id
			})
			break
		}
	}

	ramPolicyBytes, err := json.Marshal(ramPolicy)
	if err != nil {
		return "", fmt.Errorf("failed to marshal RAM policy: %w", err)
	}
	return string(ramPolicyBytes), nil
}
