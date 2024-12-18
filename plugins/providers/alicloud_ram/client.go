package alicloud_ram

import (
	"context"
	"fmt"
	"strings"

	openapi "github.com/alibabacloud-go/darabonba-openapi/v2/client"
	ram "github.com/alibabacloud-go/ram-20150501/v2/client"
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
)

type aliCloudRAMClient struct {
	accessKeyId     string
	accessKeySecret string
	ramRole         string // example: `acs:ram::{MAIN_ACCOUNT_ID}:role/{ROLE_NAME}`
}

// NewAliCloudRAMClient initializes a new instance of AliCloudRAMClient.
//
// This function creates and configures an `aliCloudRAMClient` with the provided credentials
// and resource information. If a role ARN (`ramRole`) is specified, it will
// be included in the configuration for assuming a RAM role. The function also
// validates the configuration by attempting to create a new RAM client instance.
func NewAliCloudRAMClient(accessKeyID, accessKeySecret, ramRole string) (AliCloudRAMClient, error) {
	c := &aliCloudRAMClient{
		accessKeyId:     accessKeyID,
		accessKeySecret: accessKeySecret,
		ramRole:         ramRole,
	}

	// Validate the configuration by attempting to create a new request client
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
		Type:            bptr.FromString(aliAccountTypeAccessKey),
		AccessKeyId:     &c.accessKeyId,
		AccessKeySecret: &c.accessKeySecret,
	}

	// If a role to assume is specified, configure credentials to assume the role (RAM Role)
	if c.ramRole != "" {
		credentialConfig.Type = bptr.FromString(aliAccountTypeRamRoleARN)
		credentialConfig.RoleArn = &c.ramRole
		credentialConfig.RoleSessionExpiration = bptr.FromInt(aliRoleSessionExpiration)
	}

	credential, err := credentials.NewCredential(credentialConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to create a new credentials: %w", err)
	}

	reqClient, err := ram.NewClient(&openapi.Config{Credential: credential})
	if err != nil {
		return nil, fmt.Errorf("failed to create RAM client: %w", err)
	}

	return reqClient, nil
}
