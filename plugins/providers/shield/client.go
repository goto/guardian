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

	"github.com/go-playground/validator/v10"
	"github.com/goto/guardian/pkg/log"
	"github.com/goto/guardian/pkg/opentelemetry"
	"github.com/mitchellh/mapstructure"
)

type successAccess interface{}

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
		httpClient = opentelemetry.NewHttpClient("ShieldHttpClient")
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

func (c *client) GetTeams(ctx context.Context) ([]*Group, error) {
	req, err := c.newRequest(http.MethodGet, groupsEndpoint, nil, "")
	if err != nil {
		return nil, err
	}

	var teams []*Group
	var response interface{}
	if _, err := c.do(ctx, req, &response); err != nil {
		return nil, err
	}

	if v, ok := response.(map[string]interface{}); ok && v[groupsConst] != nil {
		err = mapstructure.Decode(v[groupsConst], &teams)
	}

	for _, team := range teams {
		admins, err := c.GetAdminsOfGivenResourceType(ctx, team.ID, groupsEndpoint)
		if err != nil {
			return nil, err
		}
		team.Admins = admins
	}

	c.logger.Info(ctx, "Fetch teams from request", "total", len(teams), req.URL)

	return teams, err
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

func (c *client) GrantTeamAccess(ctx context.Context, resource *Group, userId string, role string) error {
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

	c.logger.Info(ctx, "Team access to the user,", "total users", len(users), req.URL)

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

func (c *client) RevokeTeamAccess(ctx context.Context, resource *Group, userId string, role string) error {
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

	c.logger.Info(ctx, "Remove access of the user from team,", "Users", userId, req.URL)
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

	if resp.StatusCode == http.StatusBadRequest || resp.StatusCode == http.StatusInternalServerError {
		byteData, _ := io.ReadAll(resp.Body)
		return nil, errors.New(string(byteData))
	}

	if v != nil {
		err = json.NewDecoder(resp.Body).Decode(v)
	}

	return resp, err
}
