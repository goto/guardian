package shield

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"path"
	"time"

	"github.com/go-playground/validator/v10"
	"github.com/goto/guardian/pkg/log"
	"github.com/goto/guardian/pkg/opentelemetry/otelhttpclient"
	"github.com/mitchellh/mapstructure"
)

type successAccess interface{}

const (
	MemberRole = "team_member"
	AdminRole  = "team_admin"
)

type client struct {
	baseURL *url.URL

	authHeader string
	authEmail  string

	httpClient HTTPClient
	logger     log.Logger
}

func NewClient(config *ClientConfig, logger log.Logger) (*client, error) {
	if err := validator.New().Struct(config); err != nil {
		return nil, err
	}

	baseURL, err := url.Parse(config.Host)
	if err != nil {
		return nil, err
	}

	httpClient := config.HTTPClient
	if httpClient == nil {
		httpClient = otelhttpclient.New("ShieldHttpClient", nil)
	}

	c := &client{
		baseURL:    baseURL,
		authHeader: config.AuthHeader,
		authEmail:  config.AuthEmail,
		httpClient: httpClient,
		logger:     logger,
	}

	return c, nil
}

func (c *client) newRequest(method, path string, body interface{}, authEmail string) (*http.Request, error) {
	u, err := c.baseURL.Parse(path)
	if err != nil {
		return nil, err
	}
	var buf io.ReadWriter
	if body != nil {
		buf = new(bytes.Buffer)
		err := json.NewEncoder(buf).Encode(body)
		if err != nil {
			return nil, err
		}
	}
	req, err := http.NewRequest(method, u.String(), buf)
	if err != nil {
		return nil, err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if authEmail == "" {
		req.Header.Set(c.authHeader, c.authEmail)
	} else {
		req.Header.Set(c.authHeader, authEmail)
	}
	req.Header.Set("Accept", "application/json")
	return req, nil
}

func (c *client) GetAdminsOfGivenResourceType(ctx context.Context, id string, resourceTypeEndPoint string) ([]string, error) {
	endPoint := path.Join(resourceTypeEndPoint, "/", id, "/admins")
	req, err := c.newRequest(http.MethodGet, endPoint, nil, "")
	if err != nil {
		return nil, err
	}

	var users []*User
	var response interface{}
	if _, err := c.do(ctx, req, &response); err != nil {
		return nil, err
	}
	if v, ok := response.(map[string]interface{}); ok && v[usersConst] != nil {
		err = mapstructure.Decode(v[usersConst], &users)
	}

	var userEmails []string
	for _, user := range users {
		userEmails = append(userEmails, user.Email)
	}

	return userEmails, err
}

func (c *client) GetGroups(ctx context.Context) ([]*Group, error) {
	req, err := c.newRequest(http.MethodGet, groupsEndpoint, nil, "")
	if err != nil {
		return nil, err
	}

	var groups []*Group
	var response interface{}
	if _, err := c.do(ctx, req, &response); err != nil {
		return nil, err
	}

	if v, ok := response.(map[string]interface{}); ok && v[groupsConst] != nil {
		err = mapstructure.Decode(v[groupsConst], &groups)
	}

	for _, group := range groups {
		admins, err := c.GetAdminsOfGivenResourceType(ctx, group.ID, groupsEndpoint)
		if err != nil {
			return nil, err
		}
		group.Admins = admins
	}

	c.logger.Info(ctx, "Fetch groups from request", "total", len(groups), req.URL)

	return groups, err
}

func (c *client) GetProjects(ctx context.Context) ([]*Project, error) {
	req, err := c.newRequest(http.MethodGet, projectsEndpoint, nil, "")
	if err != nil {
		return nil, err
	}

	var projects []*Project
	var response interface{}

	if _, err := c.do(ctx, req, &response); err != nil {
		return nil, err
	}

	if v, ok := response.(map[string]interface{}); ok && v[projectsConst] != nil {
		err = mapstructure.Decode(v[projectsConst], &projects)
	}

	for _, project := range projects {
		admins, err := c.GetAdminsOfGivenResourceType(ctx, project.ID, projectsEndpoint)
		if err != nil {
			return nil, err
		}
		project.Admins = admins
	}

	c.logger.Info(ctx, "Fetch projects from request", "total", len(projects), req.URL)

	return projects, err
}

func (c *client) GetOrganizations(ctx context.Context) ([]*Organization, error) {
	req, err := c.newRequest(http.MethodGet, organizationEndpoint, nil, "")
	if err != nil {
		return nil, err
	}

	var organizations []*Organization
	var response interface{}
	if _, err := c.do(ctx, req, &response); err != nil {
		return nil, err
	}

	if v, ok := response.(map[string]interface{}); ok && v[organizationsConst] != nil {
		err = mapstructure.Decode(v[organizationsConst], &organizations)
	}

	for _, org := range organizations {
		admins, err := c.GetAdminsOfGivenResourceType(ctx, org.ID, organizationEndpoint)
		if err != nil {
			return nil, err
		}
		org.Admins = admins
	}

	c.logger.Info(ctx, "Fetch organizations from request", "total", len(organizations), req.URL)

	return organizations, err
}

func (c *client) GrantGroupAccess(ctx context.Context, resource *Group, userId string, role string) error {
	body := make(map[string][]string)
	body["userIds"] = append(body["userIds"], userId)

	endPoint := path.Join(groupsEndpoint, "/", resource.ID, "/", role)
	req, err := c.newRequest(http.MethodPost, endPoint, body, "")
	if err != nil {
		return err
	}

	var users []*User
	var response interface{}
	if _, err := c.do(ctx, req, &response); err != nil {
		return err
	}

	if v, ok := response.(map[string]interface{}); ok && v[usersConst] != nil {
		err = mapstructure.Decode(v[usersConst], &users)
		if err != nil {
			return err
		}
	}

	c.logger.Info(ctx, "group access to the user,", "total users", len(users), req.URL)

	return nil
}

func (c *client) GrantProjectAccess(ctx context.Context, resource *Project, userId string, role string) error {
	body := make(map[string][]string)
	body["userIds"] = append(body["userIds"], userId)

	endPoint := path.Join(projectsEndpoint, "/", resource.ID, "/", role)
	req, err := c.newRequest(http.MethodPost, endPoint, body, "")
	if err != nil {
		return err
	}

	var users []*User
	var response interface{}
	if _, err := c.do(ctx, req, &response); err != nil {
		return err
	}

	if v, ok := response.(map[string]interface{}); ok && v[usersConst] != nil {
		err = mapstructure.Decode(v[usersConst], &users)
		if err != nil {
			return err
		}
	}

	c.logger.Info(ctx, "Project access to the user,", "total users", len(users), req.URL)
	return nil
}

func (c *client) GrantOrganizationAccess(ctx context.Context, resource *Organization, userId string, role string) error {
	body := make(map[string][]string)
	body["userIds"] = append(body["userIds"], userId)

	endPoint := path.Join(organizationEndpoint, "/", resource.ID, "/", role)
	req, err := c.newRequest(http.MethodPost, endPoint, body, "")

	if err != nil {
		return err
	}

	var users []*User
	var response interface{}
	if _, err := c.do(ctx, req, &response); err != nil {
		return err
	}

	if v, ok := response.(map[string]interface{}); ok && v[usersConst] != nil {
		err = mapstructure.Decode(v[usersConst], &users)
		if err != nil {
			return err
		}
	}

	c.logger.Info(ctx, "Organization access to the user,", "total users", len(users), req.URL)
	return nil
}

func (c *client) RevokeGroupAccess(ctx context.Context, resource *Group, userId string, role string) error {
	endPoint := path.Join(groupsEndpoint, "/", resource.ID, "/", role, "/", userId)
	req, err := c.newRequest(http.MethodDelete, endPoint, "", "")
	if err != nil {
		return err
	}

	var success successAccess
	var response interface{}
	if _, err := c.do(ctx, req, &response); err != nil {
		return err
	}

	if v, ok := response.(map[string]interface{}); ok && v != nil {
		err = mapstructure.Decode(v, &success)
		if err != nil {
			return err
		}
	}

	c.logger.Info(ctx, "Remove access of the user from group,", "Users", userId, req.URL)
	return nil
}

func (c *client) RevokeProjectAccess(ctx context.Context, resource *Project, userId string, role string) error {
	endPoint := path.Join(projectsEndpoint, "/", resource.ID, "/", role, "/", userId)
	req, err := c.newRequest(http.MethodDelete, endPoint, "", "")
	if err != nil {
		return err
	}

	var success successAccess
	var response interface{}
	if _, err := c.do(ctx, req, &response); err != nil {
		return err
	}

	if v, ok := response.(map[string]interface{}); ok && v != nil {
		err = mapstructure.Decode(v, &success)
		if err != nil {
			return err
		}
	}

	c.logger.Info(ctx, "Remove access of the user from project", "Users", userId, req.URL)
	return nil
}

func (c *client) RevokeOrganizationAccess(ctx context.Context, resource *Organization, userId string, role string) error {
	endPoint := path.Join(organizationEndpoint, "/", resource.ID, "/", role, "/", userId)
	req, err := c.newRequest(http.MethodDelete, endPoint, "", "")
	if err != nil {
		return err
	}

	var success successAccess
	var response interface{}
	if _, err := c.do(ctx, req, &response); err != nil {
		return err
	}

	if v, ok := response.(map[string]interface{}); ok && v != nil {
		err = mapstructure.Decode(v, &success)
		if err != nil {
			return err
		}
	}

	c.logger.Info(ctx, "Remove access of the user from organization", "Users", userId, req.URL)
	return nil
}

func (c *client) GetSelfUser(ctx context.Context, email string) (*User, error) {
	req, err := c.newRequest(http.MethodGet, selfUserEndpoint, nil, email)
	if err != nil {
		return nil, err
	}

	var user *User
	var response interface{}
	if _, err := c.do(ctx, req, &response); err != nil {
		return nil, err
	}

	if v, ok := response.(map[string]interface{}); ok && v[userConst] != nil {
		err = mapstructure.Decode(v[userConst], &user)
	}
	if err != nil {
		return nil, err
	}
	if user == nil {
		return nil, fmt.Errorf("shield self user response missing user for email %q", email)
	}

	c.logger.Info(ctx, "Fetch user from request", "Id", user.ID, req.URL)

	return user, err
}

func (c *client) do(ctx context.Context, req *http.Request, v interface{}) (*http.Response, error) {
	resp, err := c.httpClient.Do(req)
	if err != nil {
		c.logger.Error(ctx, fmt.Sprintf("Failed to execute request %v with error %v", req.URL, err))
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		byteData, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("request to %s failed with status %d: %s", req.URL, resp.StatusCode, string(byteData))
	}

	if v != nil {
		err = json.NewDecoder(resp.Body).Decode(v)
	}

	return resp, err
}

// dummy functions for shieldNewclient to implement the interface
func (c *client) GetResources(ctx context.Context, namespace string) ([]*Resource, error) {
	c.logger.Info(ctx, "GetResources not implemented yet", "namespace", namespace)
	return nil, errors.New("GetResources not implemented yet")
}

func (c *client) GrantResourceAccess(ctx context.Context, resource *Resource, userId string, role string) error {
	c.logger.Info(ctx, "GrantResourceAccess not implemented yet", "userId", userId)
	return errors.New("GrantResourceAccess not implemented yet")
}

func (c *client) RevokeResourceAccess(ctx context.Context, resource *Resource, userId string, role string) error {
	c.logger.Info(ctx, "RevokeResourceAccess not implemented yet", "userId", userId)
	return errors.New("RevokeResourceAccess not implemented yet")
}

func (c *client) GetNamespaces(ctx context.Context) ([]*Namespace, error) {
	c.logger.Info(ctx, "GetNamespaces not implemented yet")
	return nil, errors.New("GetNamespaces not implemented yet")
}

func (c *client) CreateTeam(ctx context.Context, team Group) (*Group, error) {
	payload := map[string]interface{}{
		"name":  team.Name,
		"slug":  team.Slug,
		"orgId": team.OrgId,
	}

	req, err := c.newRequest(http.MethodPost, groupsEndpoint, payload, "")
	if err != nil {
		return nil, err
	}

	var createdGroup *Group
	var response interface{}
	if _, err := c.do(ctx, req, &response); err != nil {
		return nil, err
	}

	if v, ok := response.(map[string]interface{}); ok && v["group"] != nil {
		if err := mapstructure.Decode(v["group"], &createdGroup); err != nil {
			return nil, err
		}
	}

	if createdGroup == nil {
		return nil, fmt.Errorf("unexpected response from shield: group not found in response body")
	}

	c.logger.Info(ctx, "Team created in shield", "id", createdGroup.ID, "name", createdGroup.Name)
	return createdGroup, nil
}

func (c *client) GrantCreateTeamAccess(ctx context.Context, team Group, userId string) (*Group, error) {
	createdGroup, err := c.CreateTeam(ctx, team)
	if err != nil {
		return nil, fmt.Errorf("creating team in shield: %w", err)
	}
	c.logger.Info(ctx, "Granting team access to user via team creation in shield", "teamId", createdGroup.ID, "userId", userId)
	if err := c.CreateRelation(ctx, createdGroup.ID, groupNamespaceConst, userId, AdminRole, "team"); err != nil {
		return nil, fmt.Errorf("creating manager relation for team %s: %w", createdGroup.ID, err)
	}
	if err := c.CreateRelation(ctx, createdGroup.ID, groupNamespaceConst, userId, MemberRole, "team"); err != nil {
		return nil, fmt.Errorf("creating manager relation for team %s: %w", createdGroup.ID, err)
	}
	c.logger.Info(ctx, "Team access granted via team creation in shield", "id", createdGroup.ID, "name", createdGroup.Name)
	return createdGroup, nil
}

func (c *client) RevokeCreateTeamAccess(ctx context.Context, team Group) error {
	c.logger.Info(ctx, "RevokeCreateTeamAccess not implemented yet")
	return errors.New("RevokeCreateTeamAccess not implemented yet")
}

func (c *client) CreateRelation(ctx context.Context, objectId string, objectNamespace string, subject string, role string, objectType string) error {
	body := Relation{
		ObjectId:    objectId,
		ObjectType:  objectType,
		SubjectType: "user",
		SubjectId:   subject,
		RoleID:      role,
	}
	c.logger.Info(ctx, "Creating relation in shield", "objectId", objectId, "objectNamespace", objectNamespace, "subject", subject)

	const maxRetries = 3
	var lastErr error
	for attempt := 0; attempt < maxRetries; attempt++ {
		if attempt > 0 {
			time.Sleep(time.Duration(attempt) * 100 * time.Millisecond)
		}

		req, err := c.newRequest(http.MethodPost, relationsEndpoint, body, "")
		if err != nil {
			return err
		}

		var relation *Relation
		var response interface{}
		if _, err := c.do(ctx, req, &response); err != nil {
			lastErr = err
			c.logger.Warn(ctx, "CreateRelation attempt failed", "attempt", attempt+1, "error", err)
			continue
		}

		if v, ok := response.(map[string]interface{}); ok && v[relationConst] != nil {
			if err = mapstructure.Decode(v[relationConst], &relation); err != nil {
				return err
			}
		}

		if relation == nil {
			lastErr = fmt.Errorf("relation not returned in response for namespace %s", objectNamespace)
			c.logger.Warn(ctx, "CreateRelation attempt returned no relation in response", "attempt", attempt+1)
			continue
		}

		c.logger.Info(ctx, "Relation created for namespace ", objectNamespace, "relation id", relation.Id)
		return nil
	}

	return fmt.Errorf("failed to create relation after %d attempts: %w", maxRetries, lastErr)
}

func (c *client) CheckUserPermission(ctx context.Context, permissions []ResourcePermission) error {
	endpoint := fmt.Sprintf(userCheckEndpoint, c.authEmail)
	body := map[string]interface{}{
		"resource_permissions": permissions,
	}
	req, err := c.newRequest(http.MethodPost, endpoint, body, "")
	if err != nil {
		return err
	}

	var response map[string]interface{}
	if _, err := c.do(ctx, req, &response); err != nil {
		return fmt.Errorf("permission check failed: %w", err)
	}

	if status, ok := response["status"].(string); !ok || status != "allowed" {
		return fmt.Errorf("permission denied: guardian service account does not have required permissions on the organization")
	}
	return nil
}
