package googlegroup

import (
	"context"
	"fmt"

	"golang.org/x/oauth2/google"
	admin "google.golang.org/api/admin/directory/v1"
	"google.golang.org/api/option"
)

type GoogleAdminService struct {
	service *admin.Service
}

func newAdminService(ctx context.Context, saKey []byte, impersonateUser string) (*GoogleAdminService, error) {
	conf, err := google.JWTConfigFromJSON(saKey,
		admin.AdminDirectoryGroupScope,
		admin.AdminDirectoryGroupMemberScope,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create JWT config from JSON: %w", err)
	}

	conf.Subject = impersonateUser

	client := conf.Client(ctx)
	service, err := admin.NewService(ctx, option.WithHTTPClient(client))
	if err != nil {
		return nil, fmt.Errorf("failed to create admin service: %w", err)
	}

	return &GoogleAdminService{service: service}, nil
}

func (m *GoogleAdminService) ListGroups(ctx context.Context, customer string, pageToken string) ([]*admin.Group, string, error) {
	groupsResp, err := m.service.Groups.List().
		Customer(customer).
		PageToken(pageToken).
		Do()
	if err != nil {
		return nil, pageToken, err
	}

	if groupsResp == nil {
		return nil, "", nil
	}

	return groupsResp.Groups, groupsResp.NextPageToken, nil
}

func (m *GoogleAdminService) InsertMember(ctx context.Context, groupKey string, member *admin.Member) (*admin.Member, error) {
	member, err := m.service.Members.Insert(groupKey, member).Do()
	if err != nil {
		return nil, err
	}
	return member, nil
}

func (m *GoogleAdminService) RemoveMember(ctx context.Context, groupKey string, memberKey string) error {
	err := m.service.Members.Delete(groupKey, memberKey).Do()
	if err != nil {
		return err
	}
	return nil
}
