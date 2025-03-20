package alicatalogapis

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/goto/guardian/pkg/slices"
)

// ---------------------------------------------------------------------------------------------------------------------
// Create
// ---------------------------------------------------------------------------------------------------------------------

type RoleBindingSchemaCreateRequest struct {
	Project             string
	Schema              string
	RoleName            string
	Members             []string
	IgnoreAlreadyExists bool
}

func (c *client) RoleBindingSchemaCreate(ctx context.Context, in *RoleBindingSchemaCreateRequest) (*RoleBinding, error) {
	// validation
	if in == nil {
		in = new(RoleBindingSchemaCreateRequest)
	}
	if in.Project == "" {
		return nil, ErrRoleBindingSchemaMissingProject.New()
	}
	if in.Schema == "" {
		return nil, ErrRoleBindingSchemaMissingSchema.New()
	}
	if in.RoleName == "" {
		return nil, ErrRoleBindingSchemaMissingRole.New()
	}
	in.Members = slices.GenericsStandardizeSlice(in.Members)
	if len(in.Members) == 0 {
		return nil, ErrRoleBindingSchemaEmptyMemberToBind.New(in.RoleName)
	}
	binding, err := c.RoleBindingSchemaGetAll(ctx, &RoleBindingSchemaGetAllRequest{
		Project: in.Project,
		Schema:  in.Schema,
	})
	if err != nil {
		return nil, err
	}
	err = binding.add(in.RoleName, in.Members, in.IgnoreAlreadyExists)
	if err != nil {
		return nil, ErrRoleBindingSchemaMemberAlreadyExist.New(err)
	}
	binding.Policy.toAliFormat(c.accountID)

	// construct request params
	method := http.MethodPost
	path := fmt.Sprintf("api/catalog/v1alpha/projects/%v/schemas/%v:setPolicy", in.Project, in.Schema)
	params := url.Values{"principleFormat": []string{"id"}}
	body, err := json.Marshal(binding)
	if err != nil {
		return nil, ErrRoleBindingSchemaFailMarshalJSON.New(in, err)
	}

	// request
	policy := new(RoleBindingPolicy)
	defer policy.toUserFormat()
	if err = c.sendRequestAndUnmarshal(ctx, method, path, params, nil, body, http.StatusOK, policy); err != nil {
		if strings.Contains(err.Error(), "role does not exists") {
			return nil, ErrRoleBindingSchemaRoleNotExist.New(in.RoleName, err)
		}
		return nil, ErrRoleBindingSchemaBadRequest.New(err)
	}
	return &RoleBinding{Policy: policy}, nil
}

// ---------------------------------------------------------------------------------------------------------------------
// Get
// ---------------------------------------------------------------------------------------------------------------------

type RoleBindingSchemaGetRequest struct {
	Project  string
	Schema   string
	RoleName string
}

func (c *client) RoleBindingSchemaGet(ctx context.Context, in *RoleBindingSchemaGetRequest) (*RoleBinding, error) {
	// validation
	if in == nil {
		in = new(RoleBindingSchemaGetRequest)
	}
	if in.Project == "" {
		return nil, ErrRoleBindingSchemaMissingProject.New()
	}
	if in.Schema == "" {
		return nil, ErrRoleBindingSchemaMissingSchema.New()
	}
	if in.RoleName == "" {
		return nil, ErrRoleBindingSchemaMissingRole.New()
	}

	// request
	binding, err := c.RoleBindingSchemaGetAll(ctx, &RoleBindingSchemaGetAllRequest{
		Project: in.Project,
		Schema:  in.Schema,
	})
	if err != nil {
		return nil, err
	}
	err = binding.collect(in.RoleName)
	if err != nil {
		return nil, ErrRoleBindingSchemaRoleNotExist.New(in.RoleName, err)
	}
	return binding, nil
}

// ---------------------------------------------------------------------------------------------------------------------
// Get All
// ---------------------------------------------------------------------------------------------------------------------

type RoleBindingSchemaGetAllRequest struct {
	Project string
	Schema  string
}

func (c *client) RoleBindingSchemaGetAll(ctx context.Context, in *RoleBindingSchemaGetAllRequest) (*RoleBinding, error) {
	// validation
	if in == nil {
		in = new(RoleBindingSchemaGetAllRequest)
	}
	if in.Project == "" {
		return nil, ErrRoleBindingSchemaMissingProject.New()
	}
	if in.Schema == "" {
		return nil, ErrRoleBindingSchemaMissingSchema.New()
	}

	// construct request params
	method := http.MethodPost
	path := fmt.Sprintf("api/catalog/v1alpha/projects/%v/schemas/%v:getPolicy", in.Project, in.Schema)
	params := url.Values{"principleFormat": []string{"id"}}

	// request
	policy := new(RoleBindingPolicy)
	defer policy.toUserFormat()
	if err := c.sendRequestAndUnmarshal(ctx, method, path, params, nil, nil, http.StatusOK, policy); err != nil {
		return nil, ErrRoleBindingSchemaBadRequest.New(err)
	}
	return &RoleBinding{Policy: policy}, nil
}

// -----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
// Delete
// ---------------------------------------------------------------------------------------------------------------------

type RoleBindingSchemaDeleteRequest struct {
	Project         string
	Schema          string
	RoleName        string
	Members         []string
	IgnoreNotExists bool
}

func (c *client) RoleBindingSchemaDelete(ctx context.Context, in *RoleBindingSchemaDeleteRequest) error {
	// validation
	if in == nil {
		in = new(RoleBindingSchemaDeleteRequest)
	}
	if in.Project == "" {
		return ErrRoleBindingSchemaMissingProject.New()
	}
	if in.Schema == "" {
		return ErrRoleBindingSchemaMissingSchema.New()
	}
	if in.RoleName == "" {
		return ErrRoleBindingSchemaMissingRole.New()
	}
	in.Members = slices.GenericsStandardizeSlice(in.Members)
	if len(in.Members) == 0 {
		return ErrRoleBindingSchemaEmptyMemberToUnbind.New(in.RoleName)
	}
	binding, err := c.RoleBindingSchemaGetAll(ctx, &RoleBindingSchemaGetAllRequest{
		Project: in.Project,
		Schema:  in.Schema,
	})
	if err != nil {
		return err
	}
	err = binding.reduce(in.RoleName, in.Members, in.IgnoreNotExists)
	if err != nil {
		return ErrRoleBindingSchemaMemberOrRoleNotExist.New(err)
	}
	binding.Policy.toAliFormat(c.accountID)

	// construct request params
	method := http.MethodPost
	path := fmt.Sprintf("api/catalog/v1alpha/projects/%v/schemas/%v:setPolicy", in.Project, in.Schema)
	params := url.Values{"principleFormat": []string{"id"}}
	body, err := json.Marshal(binding)
	if err != nil {
		return ErrRoleBindingSchemaFailMarshalJSON.New(in, err)
	}

	// request
	if err = c.sendRequest(ctx, method, path, params, nil, body, http.StatusOK); err != nil {
		return ErrRoleBindingSchemaBadRequest.New(err)
	}
	return nil
}
