package alicloud_ram

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	sso "github.com/alibabacloud-go/cloudsso-20210515/client"
	openapi "github.com/alibabacloud-go/darabonba-openapi/v2/client"
	"github.com/alibabacloud-go/tea/tea"
	"github.com/bearaujus/bptr"
)

const (
	// targetTypeRDAccount is the CloudSSO provisioning target type that maps to
	// accounts in the resource directory.
	targetTypeRDAccount = "RD-Account"

	// provisioning task statuses returned by GetTaskStatus.
	taskStatusInProgress = "InProgress"
	taskStatusSuccess    = "Success"
	taskStatusFailed     = "Failed"

	// provisioning task polling configuration.
	provisioningPollInterval = 3 * time.Second
	provisioningPollTimeout  = 5 * time.Minute
)

// cloudSSOClient is the subset of the CloudSSO SDK used for access_config grants.
type cloudSSOClient interface {
	AddPermissionPolicyToAccessConfiguration(request *sso.AddPermissionPolicyToAccessConfigurationRequest) (*sso.AddPermissionPolicyToAccessConfigurationResponse, error)
	RemovePermissionPolicyFromAccessConfiguration(request *sso.RemovePermissionPolicyFromAccessConfigurationRequest) (*sso.RemovePermissionPolicyFromAccessConfigurationResponse, error)
	ProvisionAccessConfiguration(request *sso.ProvisionAccessConfigurationRequest) (*sso.ProvisionAccessConfigurationResponse, error)
	GetTaskStatus(request *sso.GetTaskStatusRequest) (*sso.GetTaskStatusResponse, error)
	ListAccessConfigurationProvisionings(request *sso.ListAccessConfigurationProvisioningsRequest) (*sso.ListAccessConfigurationProvisioningsResponse, error)
}

// defaultSSOClient builds a real CloudSSO SDK client using the same credentials
// as the RAM client. AliCloud SDK clients are not concurrency-safe, so a new
// client is created per request.
func (c *aliCloudRAMClient) defaultSSOClient() (cloudSSOClient, error) {
	credential, err := c.buildCredential()
	if err != nil {
		return nil, err
	}

	endpoint := fmt.Sprintf("cloudsso.%s.aliyuncs.com", c.regionId)
	client, err := sso.NewClient(&openapi.Config{
		Credential: credential,
		RegionId:   bptr.FromStringNilAble(c.regionId),
		Endpoint:   bptr.FromStringNilAble(endpoint),
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create CloudSSO client: %w", err)
	}

	return client, nil
}

// GrantAccessToAccessConfig attaches the given RAM system policies to a CloudSSO
// access configuration and re-provisions it to every child account it is linked
// to, blocking until each provisioning task completes.
func (c *aliCloudRAMClient) GrantAccessToAccessConfig(ctx context.Context, policyNames []string, accessConfigID string) error {
	if c.directoryID == "" {
		return ErrMissingDirectoryID
	}

	ssoClient, err := c.newSSOClient()
	if err != nil {
		return err
	}

	for _, policyName := range policyNames {
		if _, err := ssoClient.AddPermissionPolicyToAccessConfiguration(&sso.AddPermissionPolicyToAccessConfigurationRequest{
			DirectoryId:           bptr.FromStringNilAble(c.directoryID),
			AccessConfigurationId: bptr.FromStringNilAble(accessConfigID),
			PermissionPolicyType:  bptr.FromStringNilAble(PolicyTypeSystem),
			PermissionPolicyName:  bptr.FromStringNilAble(policyName),
		}); err != nil && !isAccessConfigPolicyAlreadyExistsErr(err) {
			return fmt.Errorf("failed to add system policy %q to access configuration %q: %w", policyName, accessConfigID, err)
		}
	}

	return c.reprovisionAccessConfig(ctx, ssoClient, accessConfigID)
}

// RevokeAccessFromAccessConfig detaches the given RAM system policies from a
// CloudSSO access configuration and re-provisions it to every child account it
// is linked to.
func (c *aliCloudRAMClient) RevokeAccessFromAccessConfig(ctx context.Context, policyNames []string, accessConfigID string) error {
	if c.directoryID == "" {
		return ErrMissingDirectoryID
	}

	ssoClient, err := c.newSSOClient()
	if err != nil {
		return err
	}

	for _, policyName := range policyNames {
		if _, err := ssoClient.RemovePermissionPolicyFromAccessConfiguration(&sso.RemovePermissionPolicyFromAccessConfigurationRequest{
			DirectoryId:           bptr.FromStringNilAble(c.directoryID),
			AccessConfigurationId: bptr.FromStringNilAble(accessConfigID),
			PermissionPolicyType:  bptr.FromStringNilAble(PolicyTypeSystem),
			PermissionPolicyName:  bptr.FromStringNilAble(policyName),
		}); err != nil && !isAccessConfigPolicyNotExistsErr(err) {
			return fmt.Errorf("failed to remove system policy %q from access configuration %q: %w", policyName, accessConfigID, err)
		}
	}

	return c.reprovisionAccessConfig(ctx, ssoClient, accessConfigID)
}

// reprovisionAccessConfig re-provisions the access configuration to every
// RD-Account it is currently provisioned to, blocking until each task
// completes. If the access configuration is not provisioned anywhere, it is a
// no-op (there is nothing to propagate to).
func (c *aliCloudRAMClient) reprovisionAccessConfig(ctx context.Context, ssoClient cloudSSOClient, accessConfigID string) error {
	targetIDs, err := c.listProvisionedTargetIDs(ssoClient, accessConfigID)
	if err != nil {
		return err
	}

	for _, targetID := range targetIDs {
		if err := ctx.Err(); err != nil {
			return fmt.Errorf("failed to re-provision access configuration %q: %w", accessConfigID, err)
		}

		res, err := ssoClient.ProvisionAccessConfiguration(&sso.ProvisionAccessConfigurationRequest{
			DirectoryId:           bptr.FromStringNilAble(c.directoryID),
			AccessConfigurationId: bptr.FromStringNilAble(accessConfigID),
			TargetType:            bptr.FromStringNilAble(targetTypeRDAccount),
			TargetId:              bptr.FromStringNilAble(targetID),
		})
		if err != nil {
			return fmt.Errorf("failed to re-provision access configuration %q to account %q: %w", accessConfigID, targetID, err)
		}

		if res.Body == nil {
			continue
		}
		for _, task := range res.Body.Tasks {
			if err := c.waitForTask(ctx, ssoClient, bptr.ToStringSafe(task.TaskId)); err != nil {
				return err
			}
		}
	}

	return nil
}

// listProvisionedTargetIDs returns the IDs of all RD-Accounts the access
// configuration is currently provisioned to.
func (c *aliCloudRAMClient) listProvisionedTargetIDs(ssoClient cloudSSOClient, accessConfigID string) ([]string, error) {
	var targetIDs []string
	var nextToken *string
	for {
		res, err := ssoClient.ListAccessConfigurationProvisionings(&sso.ListAccessConfigurationProvisioningsRequest{
			DirectoryId:           bptr.FromStringNilAble(c.directoryID),
			AccessConfigurationId: bptr.FromStringNilAble(accessConfigID),
			TargetType:            bptr.FromStringNilAble(targetTypeRDAccount),
			MaxResults:            bptr.FromInt32(100),
			NextToken:             nextToken,
		})
		if err != nil {
			return nil, fmt.Errorf("failed to list provisionings for access configuration %q: %w", accessConfigID, err)
		}
		for _, prov := range res.Body.AccessConfigurationProvisionings {
			if targetID := bptr.ToStringSafe(prov.TargetId); targetID != "" {
				targetIDs = append(targetIDs, targetID)
			}
		}
		if res.Body.NextToken == nil {
			break
		}
		nextToken = res.Body.NextToken
	}

	return targetIDs, nil
}

// waitForTask polls the provisioning task until it succeeds, fails, or the
// context/timeout is reached.
func (c *aliCloudRAMClient) waitForTask(ctx context.Context, ssoClient cloudSSOClient, taskID string) error {
	if taskID == "" {
		return nil
	}

	ctx, cancel := context.WithTimeout(ctx, provisioningPollTimeout)
	defer cancel()

	ticker := time.NewTicker(provisioningPollInterval)
	defer ticker.Stop()

	for {
		res, err := ssoClient.GetTaskStatus(&sso.GetTaskStatusRequest{
			DirectoryId: bptr.FromStringNilAble(c.directoryID),
			TaskId:      bptr.FromStringNilAble(taskID),
		})
		if err != nil {
			return fmt.Errorf("failed to get provisioning task status for task %q: %w", taskID, err)
		}

		if res.Body != nil && res.Body.TaskStatus != nil {
			switch bptr.ToStringSafe(res.Body.TaskStatus.Status) {
			case taskStatusSuccess:
				return nil
			case taskStatusFailed:
				return fmt.Errorf("provisioning task %q failed: %s", taskID, bptr.ToStringSafe(res.Body.TaskStatus.FailureReason))
			case taskStatusInProgress:
				// keep polling
			}
		}

		select {
		case <-ctx.Done():
			return fmt.Errorf("failed to wait for provisioning task %q: %w", taskID, ctx.Err())
		case <-ticker.C:
		}
	}
}

// isAccessConfigPolicyAlreadyExistsErr reports whether err indicates the policy
// is already attached, so GrantAccessToAccessConfig stays idempotent.
func isAccessConfigPolicyAlreadyExistsErr(err error) bool {
	if err == nil {
		return false
	}
	var sdkErr *tea.SDKError
	if errors.As(err, &sdkErr) {
		if sdkErr.StatusCode != nil && *sdkErr.StatusCode == http.StatusConflict {
			return true
		}
		if sdkErr.Code != nil && strings.Contains(strings.ToLower(*sdkErr.Code), "alreadyexists") {
			return true
		}
	}
	return false
}

// isAccessConfigPolicyNotExistsErr reports whether err indicates the policy is
// not attached, so RevokeAccessFromAccessConfig stays idempotent.
func isAccessConfigPolicyNotExistsErr(err error) bool {
	if err == nil {
		return false
	}
	var sdkErr *tea.SDKError
	if errors.As(err, &sdkErr) {
		if sdkErr.StatusCode != nil && *sdkErr.StatusCode == http.StatusNotFound {
			return true
		}
		if sdkErr.Code != nil && strings.Contains(strings.ToLower(*sdkErr.Code), "notexist") {
			return true
		}
	}
	return false
}
