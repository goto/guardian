package alicloudiam

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
)

type iamClient struct {
	resourceName    string
	accessKeyId     string
	accessKeySecret string
	roleToAssume    string
}

// NewIamClient initializes a new instance of AliCloudIamClient.
//
// This function creates and configures an `iamClient` with the provided credentials
// and resource information. If a role ARN (`roleToAssume`) is specified, it will
// be included in the configuration for assuming a RAM role. The function also
// validates the configuration by attempting to create a new RAM client instance.
func NewIamClient(accessKeyID, accessKeySecret, resourceName, roleToAssume string) (AliCloudIamClient, error) {
	c := &iamClient{
		resourceName:    resourceName,
		accessKeyId:     accessKeyID,
		accessKeySecret: accessKeySecret,
		roleToAssume:    roleToAssume,
	}

	// Validate the configuration by attempting to create a new request client
	_, err := c.newRequestClient()
	if err != nil {
		return nil, err
	}

	return c, nil
}

func (c *iamClient) GrantAccess(_ context.Context, policyName, policyType, accountID string) error {
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

func (c *iamClient) RevokeAccess(_ context.Context, policyName, policyType, accountID string) error {
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

func (c *iamClient) GrantAccessToRole(_ context.Context, policyName, policyType, roleName string) error {
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

func (c *iamClient) RevokeAccessFromRole(_ context.Context, policyName, policyType, roleName string) error {
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

func (c *iamClient) ListAccess(_ context.Context, _ domain.ProviderConfig, _ []*domain.Resource) (domain.MapResourceAccess, error) {
	// TODO
	return nil, ErrUnimplementedMethod
}

func (c *iamClient) GetAllPoliciesByType(_ context.Context, policyType string, maxItems int32) ([]*ram.ListPoliciesResponseBodyPoliciesPolicy, error) {
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
// By default, it uses access key credentials. If a role ARN (`roleToAssume`) is specified,
// it assumes that role to generate temporary session credentials.
func (c *iamClient) newRequestClient() (*ram.Client, error) {
	// Default to access key credentials (RAM User)
	credentialConfig := &credentials.Config{
		Type:            bptr.FromString("access_key"),
		AccessKeyId:     &c.accessKeyId,
		AccessKeySecret: &c.accessKeySecret,
	}

	// If a role to assume is specified, configure credentials to assume the role (RAM Role)
	if c.roleToAssume != "" {
		credentialConfig.Type = bptr.FromString("ram_role_arn")
		credentialConfig.RoleArn = &c.roleToAssume
		credentialConfig.RoleSessionName = bptr.FromString("session2")
		credentialConfig.RoleSessionExpiration = bptr.FromInt(3600)
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
