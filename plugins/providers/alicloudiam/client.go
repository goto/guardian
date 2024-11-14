package alicloudiam

import (
	"context"
	"errors"
	"fmt"
	openapi "github.com/alibabacloud-go/darabonba-openapi/v2/client"
	ram "github.com/alibabacloud-go/ram-20150501/v2/client"
	utils "github.com/alibabacloud-go/tea-utils/v2/service"
	"github.com/aliyun/credentials-go/credentials"
	"github.com/goto/guardian/domain"
	"strings"
)

const (
	PolicyTypeSystem = "System"
	PolicyTypeCustom = "Custom"
)

type iamClient struct {
	resourceName string
	iamService   *ram.Client
}

func newIamClient(accessKeyID, accessKeySecret, resourceName string) (*iamClient, error) {
	credsConfig := new(credentials.Config).
		SetType("access_key").
		SetAccessKeyId(accessKeyID).
		SetAccessKeySecret(accessKeySecret)
	creds, err := credentials.NewCredential(credsConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to create a new credentials: %w", err)
	}

	ramClientConfig := &openapi.Config{}
	ramClientConfig.Credential = creds
	iamService, err := ram.NewClient(ramClientConfig)
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

func (c *iamClient) ListAccess(ctx context.Context, resources []*domain.Resource) (domain.MapResourceAccess, error) {
	return nil, errors.New("(c *iamClient) ListAccess: not implemented")
}
