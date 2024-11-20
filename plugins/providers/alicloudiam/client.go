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
	resourceName string
	iamService   *ram.Client
}

func NewIamClient(accessKeyID, accessKeySecret, resourceName, roleToAssume string) (AliCloudIamClient, error) {
	// Use ram user credentials by default
	credentialConfig := &credentials.Config{
		Type:            bptr.FromString("access_key"),
		AccessKeyId:     bptr.FromString(accessKeyID),
		AccessKeySecret: bptr.FromString(accessKeySecret),
	}

	// Use ram role credentials if roleToAssume is present
	if roleToAssume != "" {
		credentialConfig = &credentials.Config{
			Type:                  bptr.FromString("ram_role_arn"),
			AccessKeyId:           bptr.FromString(accessKeyID),
			AccessKeySecret:       bptr.FromString(accessKeySecret),
			RoleArn:               bptr.FromString(roleToAssume),
			RoleSessionName:       bptr.FromString("session2"),
			RoleSessionExpiration: bptr.FromInt(3600),
		}
	}

	credential, err := credentials.NewCredential(credentialConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to create a new credentials: %w", err)
	}

	iamService, err := ram.NewClient(&openapi.Config{Credential: credential})
	if err != nil {
		return nil, fmt.Errorf("failed to create RAM client: %w", err)
	}

	return &iamClient{
		resourceName: resourceName,
		iamService:   iamService,
	}, nil
}

func (c *iamClient) GrantAccess(_ context.Context, policyName, policyType, accountID string) error {
	req := &ram.AttachPolicyToUserRequest{
		PolicyName: &policyName,
		PolicyType: &policyType,
		UserName:   &accountID,
	}

	// TODO: find a way to add parent context to the request
	if _, err := c.iamService.AttachPolicyToUserWithOptions(req, &utils.RuntimeOptions{}); err != nil {
		// TODO: find the error list on SDK instead of using strings contains
		if strings.Contains(err.Error(), "EntityAlreadyExists.User.Policy") {
			return ErrPermissionAlreadyExists
		}
		return err
	}

	return nil
}

func (c *iamClient) RevokeAccess(_ context.Context, policyName, policyType, accountID string) error {
	req := &ram.DetachPolicyFromUserRequest{
		PolicyName: &policyName,
		PolicyType: &policyType,
		UserName:   &accountID,
	}

	// TODO: find a way to add parent context to the request
	if _, err := c.iamService.DetachPolicyFromUserWithOptions(req, &utils.RuntimeOptions{}); err != nil {
		// TODO: find the error list on SDK instead of using strings contains
		if strings.Contains(err.Error(), "EntityNotExist.User.Policy") {
			return ErrPermissionNotExist
		}
		return err
	}

	return nil
}

func (c *iamClient) GrantAccessToRole(_ context.Context, policyName, policyType, roleName string) error {
	req := &ram.AttachPolicyToRoleRequest{
		PolicyName: &policyName,
		PolicyType: &policyType,
		RoleName:   &roleName,
	}

	// TODO: find a way to add parent context to the request
	if _, err := c.iamService.AttachPolicyToRoleWithOptions(req, &utils.RuntimeOptions{}); err != nil {
		// TODO: find the error list on SDK instead of using strings contains
		if strings.Contains(err.Error(), "EntityAlreadyExists.Role.Policy") {
			return ErrPermissionAlreadyExists
		}
		return err
	}

	return nil
}

func (c *iamClient) RevokeAccessFromRole(_ context.Context, policyName, policyType, roleName string) error {
	req := &ram.DetachPolicyFromRoleRequest{
		PolicyName: &policyName,
		PolicyType: &policyType,
		RoleName:   &roleName,
	}

	// TODO: find a way to add parent context to the request
	if _, err := c.iamService.DetachPolicyFromRoleWithOptions(req, &utils.RuntimeOptions{}); err != nil {
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
	result := make([]*ram.ListPoliciesResponseBodyPoliciesPolicy, 0)
	var marker *string
	for {
		req := &ram.ListPoliciesRequest{
			Marker:     marker,
			MaxItems:   &maxItems,
			PolicyType: &policyType,
		}

		// TODO: find a way to add parent context to the request
		resp, err := c.iamService.ListPoliciesWithOptions(req, &utils.RuntimeOptions{})
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
