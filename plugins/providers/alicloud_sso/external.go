package alicloud_sso

import (
	"context"
	"fmt"

	sso "github.com/alibabacloud-go/cloudsso-20210515/client"
	"github.com/bearaujus/bptr"

	"github.com/goto/guardian/domain"
	"github.com/goto/guardian/pkg/aliclientmanager"
	"github.com/goto/guardian/utils"
)

// ---------------------------------------------------------------------------------------------------------------------
// Group Metadata
// ---------------------------------------------------------------------------------------------------------------------

func (p *provider) getGroups(ctx context.Context, pc *domain.ProviderConfig) ([]*domain.Resource, error) {
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("fail to retrieve groups: %w", err)
	}

	creds, err := p.getCreds(pc)
	if err != nil {
		return nil, fmt.Errorf("fail to get credentials when retrieving groups: %w", err)
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
		return nil, fmt.Errorf("fail to initialize sso client when retrieving groups: %w", err)
	}

	var groups []*sso.ListGroupsResponseBodyGroups
	var nextToken *string
	for {
		res, err := client.ListGroups(&sso.ListGroupsRequest{
			DirectoryId: bptr.FromStringNilAble(creds.DirectoryID),
			MaxResults:  bptr.FromInt32(100),
			NextToken:   nextToken,
		})
		if err != nil {
			return nil, fmt.Errorf("fail to retrieve groups: %w", err)
		}
		groups = append(groups, res.Body.Groups...)
		if res.Body.NextToken == nil {
			break
		}
		nextToken = res.Body.NextToken
	}

	resources := make([]*domain.Resource, len(groups))
	for i, group := range groups {
		groupID := bptr.ToStringSafe(group.GroupId)
		groupName := bptr.ToStringSafe(group.GroupName)
		resources[i] = &domain.Resource{
			ProviderType: pc.Type,
			ProviderURN:  pc.URN,
			Type:         resourceTypeGroup,
			URN:          groupID,
			Name:         groupName,
			GlobalURN:    utils.GetGlobalURN(sourceName, accountId, resourceTypeGroup, groupID),
		}
	}

	return resources, nil
}

// ---------------------------------------------------------------------------------------------------------------------
// Group Level Access
// ---------------------------------------------------------------------------------------------------------------------
func (p *provider) grantMemberToGroup(ctx context.Context, pc *domain.ProviderConfig, g domain.Grant) error {
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("fail to add member to group: %w", err)
	}

	if g.Resource == nil {
		return fmt.Errorf("fail to add member to group: resource is nil")
	}

	groupID := g.Resource.URN
	userID := g.AccountID

	creds, err := p.getCreds(pc)
	if err != nil {
		return fmt.Errorf("fail to read credentials when adding member to group: %w", err)
	}

	ssoClient, err := p.getSSOClient(pc)
	if err != nil {
		return fmt.Errorf("fail to initialize sso client when adding member to group: %w", err)
	}

	if _, err = ssoClient.AddUserToGroup(&sso.AddUserToGroupRequest{
		DirectoryId: bptr.FromStringNilAble(creds.DirectoryID),
		GroupId:     bptr.FromStringNilAble(groupID),
		UserId:      bptr.FromStringNilAble(userID),
	}); err != nil {
		return fmt.Errorf("fail to add member to group: %w", err)
	}

	return nil
}

func (p *provider) revokeMemberFromGroup(ctx context.Context, pc *domain.ProviderConfig, g domain.Grant) error {
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("fail to remove member from group: %w", err)
	}

	if g.Resource == nil {
		return fmt.Errorf("fail to add member to group: resource is nil")
	}

	groupID := g.Resource.URN
	userID := g.AccountID

	creds, err := p.getCreds(pc)
	if err != nil {
		return fmt.Errorf("fail to read credentials when removing member from group: %w", err)
	}

	ssoClient, err := p.getSSOClient(pc)
	if err != nil {
		return fmt.Errorf("fail to initialize sso client when removing member from group: %w", err)
	}

	if _, err = ssoClient.RemoveUserFromGroup(&sso.RemoveUserFromGroupRequest{
		DirectoryId: bptr.FromStringNilAble(creds.DirectoryID),
		GroupId:     bptr.FromStringNilAble(groupID),
		UserId:      bptr.FromStringNilAble(userID),
	}); err != nil {
		return fmt.Errorf("fail to remove member from group: %w", err)
	}

	return nil
}

// ---------------------------------------------------------------------------------------------------------------------
// External Client
// ---------------------------------------------------------------------------------------------------------------------

func (p *provider) getClientCredentials(pc *domain.ProviderConfig) (string, aliclientmanager.Credentials, error) {
	creds, err := p.getCreds(pc)
	if err != nil {
		return "", aliclientmanager.Credentials{}, err
	}

	cacheKeyFrags := fmt.Sprintf("%s:%s:%s", creds.AccessKeyID, creds.RegionID, creds.RAMRole)
	manCreds := aliclientmanager.Credentials{
		AccessKeyId:     creds.AccessKeyID,
		AccessKeySecret: creds.AccessKeySecret,
		RegionId:        creds.RegionID,
		RAMRoleARN:      creds.RAMRole,
	}

	return cacheKeyFrags, manCreds, nil
}

func (p *provider) getSSOClient(pc *domain.ProviderConfig) (*sso.Client, error) {
	cacheKeyFrags, manCreds, err := p.getClientCredentials(pc)
	if err != nil {
		return nil, err
	}

	if c, exists := p.ssoClientsCache[cacheKeyFrags]; exists {
		ssoClient, err := c.GetClient()
		if err != nil {
			return nil, err
		}
		return ssoClient, nil
	}

	clientInitFunc := func(c aliclientmanager.Credentials) (*sso.Client, error) {
		aliyunCreds, err := c.ToOpenAPIConfig()
		if err != nil {
			return nil, err
		}
		var endpoint = fmt.Sprintf("cloudsso.%s.aliyuncs.com", c.RegionId)
		aliyunCreds.Endpoint = bptr.FromStringNilAble(endpoint)
		ssoClient, err := sso.NewClient(aliyunCreds)
		if err != nil {
			return nil, err
		}
		return ssoClient, nil
	}

	manager, err := aliclientmanager.NewConfig[*sso.Client](manCreds, clientInitFunc)
	if err != nil {
		return nil, err
	}

	p.mu.Lock()
	p.ssoClientsCache[cacheKeyFrags] = manager
	p.mu.Unlock()

	return manager.GetClient()
}
