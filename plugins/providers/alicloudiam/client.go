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

func NewIamClient(accessKeyID, accessKeySecret, resourceName, roleToAssume string) (AliCloudIamClient, error) {
	c := &iamClient{
		resourceName:    resourceName,
		accessKeyId:     accessKeyID,
		accessKeySecret: accessKeySecret,
		roleToAssume:    roleToAssume,
	}

	// Test create new request client
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
		PolicyName: bptr.FromString(policyName),
		PolicyType: bptr.FromString(policyType),
		UserName:   bptr.FromString(accountID),
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
		PolicyName: bptr.FromString(policyName),
		PolicyType: bptr.FromString(policyType),
		UserName:   bptr.FromString(accountID),
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
		PolicyName: bptr.FromString(policyName),
		PolicyType: bptr.FromString(policyType),
		RoleName:   bptr.FromString(roleName),
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
		PolicyName: bptr.FromString(policyName),
		PolicyType: bptr.FromString(policyType),
		RoleName:   bptr.FromString(roleName),
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
			MaxItems:   bptr.FromInt32(maxItems),
			PolicyType: bptr.FromString(policyType),
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

func (c *iamClient) newRequestClient() (*ram.Client, error) {
	// Use ram user credentials by default
	credentialConfig := &credentials.Config{
		Type:            bptr.FromString("access_key"),
		AccessKeyId:     bptr.FromString(c.accessKeyId),
		AccessKeySecret: bptr.FromString(c.accessKeySecret),
	}
	if c.roleToAssume != "" { // Use ram role credentials if roleToAssume is present
		credentialConfig.Type = bptr.FromString("ram_role_arn")
		credentialConfig.RoleArn = bptr.FromString(c.roleToAssume)
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
