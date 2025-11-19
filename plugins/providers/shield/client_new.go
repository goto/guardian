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
	"github.com/goto/guardian/pkg/opentelemetry/otelhttpclient"
	"github.com/mitchellh/mapstructure"
)

type shieldNewclient struct {
	baseURL *url.URL

	authHeader string
	authEmail  string

	httpClient HTTPClient
	logger     log.Logger
}

func NewShieldNewClient(config *ClientConfig, logger log.Logger) (*shieldNewclient, error) {
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

	c := &shieldNewclient{
		baseURL:    baseURL,
		authHeader: config.AuthHeader,
		authEmail:  config.AuthEmail,
		httpClient: httpClient,
		logger:     logger,
	}

	return c, nil
}

func (c *shieldNewclient) newRequest(method, path string, body interface{}, authEmail string) (*http.Request, error) {
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

func (c *shieldNewclient) GetAdminsOfGivenResourceType(ctx context.Context, id string, resourceTypeEndPoint string) ([]string, error) {
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

func (c *shieldNewclient) GetGroupRelations(ctx context.Context, id string, role string) ([]string, error) {
	endPoint := fmt.Sprintf("%s/%s/relations?role=%s", groupsEndpoint, id, role)
	req, err := c.newRequest(http.MethodGet, endPoint, nil, "")
	if err != nil {
		return nil, err
	}

	var groupRelations []*GroupRelation
	var response interface{}
	if _, err := c.do(ctx, req, &response); err != nil {
		return nil, err
	}
	if v, ok := response.(map[string]interface{}); ok && v[relationsConst] != nil {
		err = mapstructure.Decode(v[relationsConst], &groupRelations)
	}

	var userEmails []string
	for _, relation := range groupRelations {
		userEmails = append(userEmails, relation.User.Email)
	}

	return userEmails, err
}

func (c *shieldNewclient) CreateRelation(ctx context.Context, objectId string, objectNamespace string, subject string, role string) error {
	body := Relation{
		ObjectId:        objectId,
		ObjectNamespace: objectNamespace,
		Subject:         subject,
		RoleName:        role,
	}
	c.logger.Info(ctx, "Creating relation", "body", fmt.Sprintf("%+v", body))
	c.logger.Warn(ctx, "Creating relation", "body", fmt.Sprintf("%+v", body))

	req, err := c.newRequest(http.MethodPost, relationsEndpoint, body, "")
	if err != nil {
		return err
	}

	var relation *Relation
	var response interface{}
	if _, err := c.do(ctx, req, &response); err != nil {
		return err
	}

	if v, ok := response.(map[string]interface{}); ok && v[relationConst] != nil {
		err = mapstructure.Decode(v[relationConst], &relation)
		if err != nil {
			return err
		}
	}

	c.logger.Info(ctx, "Relation created for namespace ", objectNamespace, "relation id", relation.Id)
	return nil
}

func (c *shieldNewclient) DeleteRelation(ctx context.Context, objectId string, subjectId string, role string) error {
	deleteRelationEndpoint := fmt.Sprintf("%s/%s/subject/%s/role/%s", objectEndpoint, objectId, subjectId, role)
	req, err := c.newRequest(http.MethodDelete, deleteRelationEndpoint, nil, "")
	if err != nil {
		return err
	}

	var response interface{}
	if _, err := c.do(ctx, req, &response); err != nil {
		return err
	}

	if v, ok := response.(map[string]interface{}); ok && v["message"] != nil {
		c.logger.Info(ctx, "Relation deleted for object", objectId, "subject", subjectId, "role", role)
		return nil
	}
	return nil
}

func (c *shieldNewclient) GetGroups(ctx context.Context) ([]*Group, error) {
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
		admins, err := c.GetGroupRelations(ctx, group.ID, managerRoleConst)
		if err != nil {
			return nil, err
		}
		group.Admins = admins
	}

	c.logger.Info(ctx, fmt.Sprintf("Fetch groups from new shield request total=%d with request %s", len(groups), req.URL))

	return groups, err
}

func (c *shieldNewclient) GetProjects(ctx context.Context) ([]*Project, error) {
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

	c.logger.Info(ctx, fmt.Sprintf("Fetch projects from new shield request total=%d with request %s", len(projects), req.URL))

	return projects, err
}

func (c *shieldNewclient) GetOrganizations(ctx context.Context) ([]*Organization, error) {
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

	c.logger.Info(ctx, fmt.Sprintf("Fetch organizations from new shield request total=%d with request %s", len(organizations), req.URL))

	return organizations, err
}

func (c *shieldNewclient) GetResources(ctx context.Context, namespace string) ([]*Resource, error) {
	var (
		allResources []*Resource
		pageSize     = 500
		pageNum      = 1
		totalFetched = 0
	)

	for {
		queryParams := url.Values{}
		if namespace != "" {
			queryParams.Set("namespace_id", namespace)
		}
		queryParams.Set("page_size", fmt.Sprintf("%d", pageSize))
		queryParams.Set("page_num", fmt.Sprintf("%d", pageNum))

		endpoint := fmt.Sprintf("%s?%s", resourcesEndpoint, queryParams.Encode())
		req, err := c.newRequest(http.MethodGet, endpoint, nil, "")
		if err != nil {
			return nil, err
		}

		var response map[string]interface{}
		if _, err := c.do(ctx, req, &response); err != nil {
			return nil, err
		}

		var resources []*Resource
		if v, ok := response[resourcesConst]; ok && v != nil {
			if err := mapstructure.Decode(v, &resources); err != nil {
				return nil, err
			}
		}

		allResources = append(allResources, resources...)
		count := len(resources)
		totalFetched += count

		// If less than pageSize returned, we've reached the end
		if count < pageSize {
			break
		}
		pageNum++
	}

	c.logger.Info(ctx, "Fetched resources from request", "total", len(allResources))
	return allResources, nil
}

func (c *shieldNewclient) GetNamespaces(ctx context.Context) ([]*Namespace, error) {
	req, err := c.newRequest(http.MethodGet, namespacesEndpoint, nil, "")
	if err != nil {
		return nil, err
	}

	var namespaces []*Namespace
	var response interface{}
	if _, err := c.do(ctx, req, &response); err != nil {
		return nil, err
	}

	if v, ok := response.(map[string]interface{}); ok && v[namespacesConst] != nil {
		err = mapstructure.Decode(v[namespacesConst], &namespaces)
	}

	c.logger.Info(ctx, fmt.Sprintf("Fetch namespaces from new shield request total=%d with request %s", len(namespaces), req.URL))

	return namespaces, err
}

func (c *shieldNewclient) GrantGroupAccess(ctx context.Context, resource *Group, userId string, role string) error {
	err := c.CreateRelation(ctx, resource.ID, groupNamespaceConst, fmt.Sprintf("%s:%s", userNamespaceConst, userId), role)
	if err != nil {
		return err
	}
	c.logger.Info(ctx, "group access created for user in new shield", userId)
	return nil
}

func (c *shieldNewclient) GrantProjectAccess(ctx context.Context, resource *Project, userId string, role string) error {
	err := c.CreateRelation(ctx, resource.ID, projectNamespaceConst, fmt.Sprintf("%s:%s", userNamespaceConst, userId), role)
	if err != nil {
		return err
	}
	c.logger.Info(ctx, "Project access created for user in new shield", userId)
	return nil
}

func (c *shieldNewclient) GrantOrganizationAccess(ctx context.Context, resource *Organization, userId string, role string) error {
	err := c.CreateRelation(ctx, resource.ID, organizationNamespaceConst, fmt.Sprintf("%s:%s", userNamespaceConst, userId), role)
	if err != nil {
		return err
	}
	c.logger.Info(ctx, "Organization access created for user in new shield", userId)
	return nil
}

func (c *shieldNewclient) GrantResourceAccess(ctx context.Context, resource *Resource, userId string, role string) error {
	resourceId := resource.URN
	if len(resourceId) > 9 && resourceId[:9] == "resource:" {
		resourceId = resourceId[9:]
	}
	c.logger.Warn(ctx, "resource ", resource)
	err := c.CreateRelation(ctx, resource.ID, resource.Namespace.ID, fmt.Sprintf("%s:%s", userNamespaceConst, userId), role)
	if err != nil {
		return err
	}
	c.logger.Info(ctx, "Resource access created for user in new shield", userId)
	return nil
}

func (c *shieldNewclient) RevokeGroupAccess(ctx context.Context, resource *Group, userId string, role string) error {
	err := c.DeleteRelation(ctx, resource.ID, userId, role)
	if err != nil {
		return err
	}
	c.logger.Info(ctx, "Remove access of the user from group in new shield,", "Users", userId, resource.ID)
	return nil
}

func (c *shieldNewclient) RevokeProjectAccess(ctx context.Context, resource *Project, userId string, role string) error {
	err := c.DeleteRelation(ctx, resource.ID, userId, role)
	if err != nil {
		return err
	}
	c.logger.Info(ctx, "Remove access of the user from project in new shield,", "Users", userId, resource.ID)
	return nil
}

func (c *shieldNewclient) RevokeOrganizationAccess(ctx context.Context, resource *Organization, userId string, role string) error {
	err := c.DeleteRelation(ctx, resource.ID, userId, role)
	if err != nil {
		return err
	}
	c.logger.Info(ctx, "Remove access of the user from organization in new shield,", "Users", userId, resource.ID)
	return nil
}

func (c *shieldNewclient) RevokeResourceAccess(ctx context.Context, resource *Resource, userId string, role string) error {
	err := c.DeleteRelation(ctx, resource.ID, userId, role)
	if err != nil {
		return err
	}
	c.logger.Info(ctx, "Remove access of the user from resource in new shield,", "Users", userId, resource.ID)
	return nil
}

func (c *shieldNewclient) GetSelfUser(ctx context.Context, email string) (*User, error) {
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

	c.logger.Info(ctx, "Fetch user from new shield request", "Id", user.ID, req.URL)

	return user, err
}

func (c *shieldNewclient) do(ctx context.Context, req *http.Request, v interface{}) (*http.Response, error) {
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
