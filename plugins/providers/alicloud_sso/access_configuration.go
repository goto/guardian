package alicloud_sso

import (
	"context"
	"fmt"
	"time"

	sso "github.com/alibabacloud-go/cloudsso-20210515/client"
	"github.com/bearaujus/bptr"
	"github.com/mitchellh/mapstructure"

	"github.com/goto/guardian/domain"
	"github.com/goto/guardian/pkg/aliclientmanager"
	"github.com/goto/guardian/utils"
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

// ---------------------------------------------------------------------------------------------------------------------
// Access Configuration Metadata
// ---------------------------------------------------------------------------------------------------------------------

func (p *provider) getAccessConfigurations(ctx context.Context, pc *domain.ProviderConfig) ([]*domain.Resource, error) {
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("fail to retrieve access configurations: %w", err)
	}

	creds, err := p.getCreds(pc)
	if err != nil {
		return nil, fmt.Errorf("fail to get credentials when retrieving access configurations: %w", err)
	}

	credentialsIdentity, err := aliclientmanager.GetCredentialsIdentity(aliclientmanager.Credentials{
		AccessKeyId:     creds.AccessKeyID,
		AccessKeySecret: creds.AccessKeySecret,
		RegionId:        creds.RegionID,
		RAMRoleARN:      creds.RAMRole,
	})
	if err != nil {
		return nil, fmt.Errorf("fail to get credentials identity: %w", err)
	}
	accountId := bptr.ToStringSafe(credentialsIdentity.AccountId)

	client, err := p.getSSOClient(pc)
	if err != nil {
		return nil, fmt.Errorf("fail to initialize sso client when retrieving access configurations: %w", err)
	}

	var accessConfigs []*sso.ListAccessConfigurationsResponseBodyAccessConfigurations
	var nextToken *string
	for {
		res, err := client.ListAccessConfigurations(&sso.ListAccessConfigurationsRequest{
			DirectoryId: bptr.FromStringNilAble(creds.DirectoryID),
			MaxResults:  bptr.FromInt32(100),
			NextToken:   nextToken,
		})
		if err != nil {
			return nil, fmt.Errorf("fail to retrieve access configurations: %w", err)
		}
		accessConfigs = append(accessConfigs, res.Body.AccessConfigurations...)
		if res.Body.NextToken == nil {
			break
		}
		nextToken = res.Body.NextToken
	}

	resources := make([]*domain.Resource, len(accessConfigs))
	for i, ac := range accessConfigs {
		acID := bptr.ToStringSafe(ac.AccessConfigurationId)
		acName := bptr.ToStringSafe(ac.AccessConfigurationName)
		resources[i] = &domain.Resource{
			ProviderType: pc.Type,
			ProviderURN:  pc.URN,
			Type:         resourceTypeAccessConfiguration,
			URN:          acID,
			Name:         acName,
			GlobalURN:    utils.GetGlobalURN(sourceName, accountId, resourceTypeAccessConfiguration, acID),
		}
	}

	return resources, nil
}

// ---------------------------------------------------------------------------------------------------------------------
// Access Configuration Level Access
// ---------------------------------------------------------------------------------------------------------------------

func (p *provider) addSystemPoliciesToAccessConfig(ctx context.Context, pc *domain.ProviderConfig, g domain.Grant) error {
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("fail to add system policy to access configuration. context error: %w", err)
	}

	if g.Resource == nil {
		return fmt.Errorf("fail to add system policy to access configuration: resource is nil")
	}
	accessConfigID := g.Resource.URN

	policyNames, err := getSystemPolicyNamesFromGrant(pc, g)
	if err != nil {
		return err
	}

	creds, err := p.getCreds(pc)
	if err != nil {
		return fmt.Errorf("fail to read credentials when adding system policy to access configuration: %w", err)
	}

	client, err := p.getSSOClient(pc)
	if err != nil {
		return fmt.Errorf("fail to initialize sso client when adding system policy to access configuration: %w", err)
	}

	for _, policyName := range policyNames {
		if _, err := client.AddPermissionPolicyToAccessConfiguration(&sso.AddPermissionPolicyToAccessConfigurationRequest{
			DirectoryId:           bptr.FromStringNilAble(creds.DirectoryID),
			AccessConfigurationId: bptr.FromStringNilAble(accessConfigID),
			PermissionPolicyType:  bptr.FromStringNilAble(permissionPolicyTypeSystem),
			PermissionPolicyName:  bptr.FromStringNilAble(policyName),
		}); err != nil && !isPolicyAlreadyExistsErr(err) {
			return fmt.Errorf("fail to add system policy %q to access configuration %q: %w", policyName, accessConfigID, err)
		}
	}

	return p.reprovisionToAllTargets(ctx, client, creds.DirectoryID, accessConfigID)
}

func (p *provider) removeSystemPoliciesFromAccessConfig(ctx context.Context, pc *domain.ProviderConfig, g domain.Grant) error {
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("fail to remove system policy from access configuration. context error: %w", err)
	}

	if g.Resource == nil {
		return fmt.Errorf("fail to remove system policy from access configuration: resource is nil")
	}
	accessConfigID := g.Resource.URN

	policyNames, err := getSystemPolicyNamesFromGrant(pc, g)
	if err != nil {
		return err
	}

	creds, err := p.getCreds(pc)
	if err != nil {
		return fmt.Errorf("fail to read credentials when removing system policy from access configuration: %w", err)
	}

	client, err := p.getSSOClient(pc)
	if err != nil {
		return fmt.Errorf("fail to initialize sso client when removing system policy from access configuration: %w", err)
	}

	for _, policyName := range policyNames {
		if _, err := client.RemovePermissionPolicyFromAccessConfiguration(&sso.RemovePermissionPolicyFromAccessConfigurationRequest{
			DirectoryId:           bptr.FromStringNilAble(creds.DirectoryID),
			AccessConfigurationId: bptr.FromStringNilAble(accessConfigID),
			PermissionPolicyType:  bptr.FromStringNilAble(permissionPolicyTypeSystem),
			PermissionPolicyName:  bptr.FromStringNilAble(policyName),
		}); err != nil && !isPolicyNotExistsErr(err) {
			return fmt.Errorf("fail to remove system policy %q from access configuration %q: %w", policyName, accessConfigID, err)
		}
	}

	return p.reprovisionToAllTargets(ctx, client, creds.DirectoryID, accessConfigID)
}

// ---------------------------------------------------------------------------------------------------------------------
// Provisioning
// ---------------------------------------------------------------------------------------------------------------------

// reprovisionToAllTargets re-provisions the access configuration to every
// RD-Account it is currently provisioned to, so that permission policy changes
// are propagated to the RAM role in each child account. It blocks until every
// provisioning task completes.
func (p *provider) reprovisionToAllTargets(ctx context.Context, client ssoClient, directoryID, accessConfigID string) error {
	targetIDs, err := p.listProvisionedTargetIDs(client, directoryID, accessConfigID)
	if err != nil {
		return err
	}

	for _, targetID := range targetIDs {
		if err := ctx.Err(); err != nil {
			return fmt.Errorf("fail to re-provision access configuration %q. context error: %w", accessConfigID, err)
		}

		res, err := client.ProvisionAccessConfiguration(&sso.ProvisionAccessConfigurationRequest{
			DirectoryId:           bptr.FromStringNilAble(directoryID),
			AccessConfigurationId: bptr.FromStringNilAble(accessConfigID),
			TargetType:            bptr.FromStringNilAble(targetTypeRDAccount),
			TargetId:              bptr.FromStringNilAble(targetID),
		})
		if err != nil {
			return fmt.Errorf("fail to re-provision access configuration %q to account %q: %w", accessConfigID, targetID, err)
		}

		if res.Body == nil {
			continue
		}
		for _, task := range res.Body.Tasks {
			if err := p.waitForTask(ctx, client, directoryID, bptr.ToStringSafe(task.TaskId)); err != nil {
				return err
			}
		}
	}

	return nil
}

// listProvisionedTargetIDs returns the IDs of all RD-Accounts the access
// configuration is currently provisioned to.
func (p *provider) listProvisionedTargetIDs(client ssoClient, directoryID, accessConfigID string) ([]string, error) {
	var targetIDs []string
	var nextToken *string
	for {
		res, err := client.ListAccessConfigurationProvisionings(&sso.ListAccessConfigurationProvisioningsRequest{
			DirectoryId:           bptr.FromStringNilAble(directoryID),
			AccessConfigurationId: bptr.FromStringNilAble(accessConfigID),
			TargetType:            bptr.FromStringNilAble(targetTypeRDAccount),
			MaxResults:            bptr.FromInt32(100),
			NextToken:             nextToken,
		})
		if err != nil {
			return nil, fmt.Errorf("fail to list provisionings for access configuration %q: %w", accessConfigID, err)
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
func (p *provider) waitForTask(ctx context.Context, client ssoClient, directoryID, taskID string) error {
	if taskID == "" {
		return nil
	}

	ctx, cancel := context.WithTimeout(ctx, provisioningPollTimeout)
	defer cancel()

	ticker := time.NewTicker(provisioningPollInterval)
	defer ticker.Stop()

	for {
		res, err := client.GetTaskStatus(&sso.GetTaskStatusRequest{
			DirectoryId: bptr.FromStringNilAble(directoryID),
			TaskId:      bptr.FromStringNilAble(taskID),
		})
		if err != nil {
			return fmt.Errorf("fail to get provisioning task status for task %q: %w", taskID, err)
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
			return fmt.Errorf("fail to wait for provisioning task %q: %w", taskID, ctx.Err())
		case <-ticker.C:
		}
	}
}

// ---------------------------------------------------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------------------------------------------------

// getSystemPolicyNamesFromGrant resolves the granted role to the list of RAM
// system policy names configured in its permissions.
func getSystemPolicyNamesFromGrant(pc *domain.ProviderConfig, g domain.Grant) ([]string, error) {
	if g.Resource == nil {
		return nil, fmt.Errorf("grant resource is nil")
	}

	var selectedResource *domain.ResourceConfig
	for _, r := range pc.Resources {
		if r.Type == g.Resource.Type {
			selectedResource = r
			break
		}
	}
	if selectedResource == nil {
		return nil, fmt.Errorf("resource with type %q does not exist in provider config", g.Resource.Type)
	}

	var selectedRole *domain.Role
	for _, r := range selectedResource.Roles {
		if r.ID == g.Role {
			selectedRole = r
			break
		}
	}
	if selectedRole == nil {
		return nil, fmt.Errorf("role %q does not exist for resource type %q", g.Role, g.Resource.Type)
	}

	policyNames := make([]string, 0, len(selectedRole.Permissions))
	for _, rawPerm := range selectedRole.Permissions {
		var policyName string
		if err := mapstructure.Decode(rawPerm, &policyName); err != nil {
			return nil, fmt.Errorf("unable to decode permission as system policy name: %w", err)
		}
		if policyName != "" {
			policyNames = append(policyNames, policyName)
		}
	}
	if len(policyNames) == 0 {
		return nil, fmt.Errorf("role %q has no system policies configured", g.Role)
	}

	return policyNames, nil
}
