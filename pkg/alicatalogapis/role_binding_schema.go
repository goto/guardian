package alicatalogapis

import (
	"context"
	"errors"
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
	Project  string
	Schema   string
	RoleName string
	Members  []string
}

func (c *client) RoleBindingSchemaCreate(ctx context.Context, in *RoleBindingSchemaCreateRequest) (*RoleBinding, error) {
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

	setPath := fmt.Sprintf("api/catalog/v1alpha/projects/%v/schemas/%v:setPolicy", in.Project, in.Schema)
	policy, err := c.readModifyWriteRoleBinding(
		ctx,
		func(ctx context.Context) (*RoleBinding, error) {
			return c.RoleBindingSchemaGetAll(ctx, &RoleBindingSchemaGetAllRequest{
				Project: in.Project,
				Schema:  in.Schema,
			})
		},
		func(binding *RoleBinding) {
			binding.add(in.RoleName, in.Members)
		},
		setPath,
	)
	if err != nil {
		return nil, wrapSchemaRoleBindingWriteErr(in, in.RoleName, err)
	}
	return &RoleBinding{Policy: policy}, nil
}

func wrapSchemaRoleBindingWriteErr(in any, roleName string, err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, errRoleBindingMarshal) {
		return ErrRoleBindingSchemaFailMarshalJSON.New(in, err)
	}
	if isRoleBindingRoleMissing(err) {
		return ErrRoleBindingSchemaRoleNotExist.New(roleName, err)
	}
	if strings.Contains(err.Error(), "alicatalogapis-role_binding_schema") {
		return err
	}
	return ErrRoleBindingSchemaBadRequest.New(err)
}

// ---------------------------------------------------------------------------------------------------------------------
// Get All
// ---------------------------------------------------------------------------------------------------------------------

type RoleBindingSchemaGetAllRequest struct {
	Project string
	Schema  string
}

func (c *client) RoleBindingSchemaGetAll(ctx context.Context, in *RoleBindingSchemaGetAllRequest) (*RoleBinding, error) {
	if in == nil {
		in = new(RoleBindingSchemaGetAllRequest)
	}
	if in.Project == "" {
		return nil, ErrRoleBindingSchemaMissingProject.New()
	}
	if in.Schema == "" {
		return nil, ErrRoleBindingSchemaMissingSchema.New()
	}

	method := http.MethodPost
	path := fmt.Sprintf("api/catalog/v1alpha/projects/%v/schemas/%v:getPolicy", in.Project, in.Schema)
	params := url.Values{"principleFormat": []string{"id"}}

	policy := new(RoleBindingPolicy)
	if err := c.sendRequestAndUnmarshal(ctx, method, path, params, nil, nil, http.StatusOK, policy); err != nil {
		return nil, ErrRoleBindingSchemaBadRequest.New(err)
	}
	policy.toUserFormat()
	return &RoleBinding{Policy: policy}, nil
}

// ---------------------------------------------------------------------------------------------------------------------
// Delete
// ---------------------------------------------------------------------------------------------------------------------

type RoleBindingSchemaDeleteRequest struct {
	Project  string
	Schema   string
	RoleName string
	Members  []string
}

func (c *client) RoleBindingSchemaDelete(ctx context.Context, in *RoleBindingSchemaDeleteRequest) error {
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

	setPath := fmt.Sprintf("api/catalog/v1alpha/projects/%v/schemas/%v:setPolicy", in.Project, in.Schema)
	_, err := c.readModifyWriteRoleBinding(
		ctx,
		func(ctx context.Context) (*RoleBinding, error) {
			return c.RoleBindingSchemaGetAll(ctx, &RoleBindingSchemaGetAllRequest{
				Project: in.Project,
				Schema:  in.Schema,
			})
		},
		func(binding *RoleBinding) {
			binding.remove(in.RoleName, in.Members)
		},
		setPath,
	)
	if err != nil {
		return wrapSchemaRoleBindingWriteErr(in, in.RoleName, err)
	}
	return nil
}
