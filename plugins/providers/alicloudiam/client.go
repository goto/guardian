package alicloudiam

import (
	"context"
	"fmt"
	openapi "github.com/alibabacloud-go/darabonba-openapi/v2/client"
	ram "github.com/alibabacloud-go/ram-20150501/v2/client"
	utils "github.com/alibabacloud-go/tea-utils/v2/service"
	"github.com/aliyun/credentials-go/credentials"
	"github.com/goto/guardian/domain"
	"golang.org/x/sync/errgroup"
	"regexp"
	"strings"
	"sync"
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

func (c *iamClient) ListAccess(ctx context.Context, _ domain.ProviderConfig, resources []*domain.Resource) (domain.MapResourceAccess, error) {
	var (
		maxFetchItem int32 = 1000
		roles        []*ram.ListRolesResponseBodyRolesRole
		users        []*ram.ListUsersResponseBodyUsersUser
	)

	mu := &sync.Mutex{}
	eg, ctx := errgroup.WithContext(ctx)

	eg.Go(func() error {
		var err error
		roles, err = c.getAllRoles(ctx, maxFetchItem)
		if err != nil {
			return err
		}
		return nil
	})

	eg.Go(func() error {
		var err error
		users, err = c.getAllUsers(ctx, maxFetchItem)
		if err != nil {
			return err
		}
		return nil
	})

	if err := eg.Wait(); err != nil {
		return nil, err
	}

	access := make(domain.MapResourceAccess)
	for _, resource := range resources {
		rCp := resource
		for _, user := range users {
			uCp := user
			eg.Go(func() error {
				policies, err := c.getPoliciesByUser(ctx, *uCp.UserName)
				if err != nil {
					return err
				}

				if len(policies) == 0 {
					return nil
				}

				aes := make([]domain.AccessEntry, len(policies))
				for i, policy := range policies {
					aes[i] = domain.AccessEntry{
						AccountType: AccountTypeRamUser,
						AccountID:   fmt.Sprintf("%v@%v%v", uCp.UserName, rCp.ProviderURN, aliAccountUserIdDomainSuffix),
						Permission:  *policy.PolicyName,
					}
				}

				mu.Lock()
				access[rCp.URN] = append(access[rCp.URN], aes...)
				mu.Unlock()
				return nil
			})
		}

		for _, role := range roles {
			roCp := role
			eg.Go(func() error {
				policies, err := c.getPoliciesByRole(ctx, *roCp.RoleName)
				if err != nil {
					return err
				}

				if len(policies) == 0 {
					return nil
				}

				aes := make([]domain.AccessEntry, len(policies))
				for i, policy := range policies {
					aes[i] = domain.AccessEntry{
						AccountType: AccountTypeRamRole,
						AccountID:   fmt.Sprintf("%v@%v%v", roCp.RoleName, rCp.ProviderURN, aliAccountUserIdDomainSuffix),
						Permission:  *policy.PolicyName,
					}
				}

				mu.Lock()
				access[rCp.URN] = append(access[rCp.URN], aes...)
				mu.Unlock()
				return nil
			})
		}
	}

	return access, nil
}

func (c *iamClient) getPoliciesByUser(_ context.Context, userName string) ([]*ram.ListPoliciesForUserResponseBodyPoliciesPolicy, error) {
	req := &ram.ListPoliciesForUserRequest{
		UserName: &userName,
	}

	// TODO: find a way to add parent context to the request
	resp, err := c.iamService.ListPoliciesForUserWithOptions(req, &utils.RuntimeOptions{})
	if err != nil {
		return nil, err
	}

	return resp.Body.Policies.Policy, nil
}

func (c *iamClient) getPoliciesByRole(_ context.Context, roleName string) ([]*ram.ListPoliciesForRoleResponseBodyPoliciesPolicy, error) {
	req := &ram.ListPoliciesForRoleRequest{
		RoleName: &roleName,
	}

	// TODO: find a way to add parent context to the request
	resp, err := c.iamService.ListPoliciesForRoleWithOptions(req, &utils.RuntimeOptions{})
	if err != nil {
		return nil, err
	}

	return resp.Body.Policies.Policy, nil
}

func (c *iamClient) getAllRoles(_ context.Context, maxItems int32) ([]*ram.ListRolesResponseBodyRolesRole, error) {
	result := make([]*ram.ListRolesResponseBodyRolesRole, 0)
	var marker *string = nil
	for {
		req := &ram.ListRolesRequest{
			Marker:   marker,
			MaxItems: &maxItems,
		}

		// TODO: find a way to add parent context to the request
		resp, err := c.iamService.ListRolesWithOptions(req, &utils.RuntimeOptions{})
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

func (c *iamClient) getAllUsers(_ context.Context, maxItems int32) ([]*ram.ListUsersResponseBodyUsersUser, error) {
	result := make([]*ram.ListUsersResponseBodyUsersUser, 0)
	var marker *string = nil
	for {
		req := &ram.ListUsersRequest{
			Marker:   marker,
			MaxItems: &maxItems,
		}

		// TODO: find a way to add parent context to the request
		resp, err := c.iamService.ListUsersWithOptions(req, &utils.RuntimeOptions{})
		if err != nil {
			return nil, err
		}

		result = append(result, resp.Body.Users.User...)
		if resp.Body.Marker == nil {
			break
		}

		marker = resp.Body.Marker
	}

	return result, nil
}

// splitAliAccountUserId splits an Alibaba Cloud account user ID into username and account ID.
// Example input: "foo.bar@12345679.onaliyun.com"
// Returns: username ("foo.bar"), accountId ("12345679"), or an error if the format is invalid.
func splitAliAccountUserId(d string) (string, string, error) {
	matched, _ := regexp.MatchString(aliAccountUserIdPattern, d)
	if !matched {
		return "", "", ErrInvalidAliAccountUserID
	}

	accountUserIDSplit := strings.Split(d, "@")
	username := accountUserIDSplit[0]
	accountId := strings.TrimSuffix(accountUserIDSplit[1], aliAccountUserIdDomainSuffix)

	return username, accountId, nil
}
