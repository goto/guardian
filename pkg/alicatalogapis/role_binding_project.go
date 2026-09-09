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

type RoleBindingProjectCreateRequest struct {
	Project  string
	RoleName string
	Members  []string
}

func (c *client) RoleBindingProjectCreate(ctx context.Context, in *RoleBindingProjectCreateRequest) (*RoleBinding, error) {
	if in == nil {
		in = new(RoleBindingProjectCreateRequest)
	}
	if in.Project == "" {
		return nil, ErrRoleBindingProjectMissingProject.New()
	}
	if in.RoleName == "" {
		return nil, ErrRoleBindingProjectMissingRole.New()
	}
	in.Members = slices.GenericsStandardizeSlice(in.Members)
	if len(in.Members) == 0 {
		return nil, ErrRoleBindingProjectEmptyMemberToBind.New(in.RoleName)
	}

	setPath := fmt.Sprintf("api/catalog/v1alpha/projects/%v:setPolicy", in.Project)
	policy, err := c.readModifyWriteRoleBinding(
		ctx,
		func(ctx context.Context) (*RoleBinding, error) {
			return c.RoleBindingProjectGetAll(ctx, &RoleBindingProjectGetAllRequest{Project: in.Project})
		},
		func(binding *RoleBinding) {
			binding.add(in.RoleName, in.Members)
		},
		setPath,
	)
	if err != nil {
		return nil, wrapProjectRoleBindingWriteErr(in, err)
	}
	return &RoleBinding{Policy: policy}, nil
}

func wrapProjectRoleBindingWriteErr(in *RoleBindingProjectCreateRequest, err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, errRoleBindingMarshal) {
		return ErrRoleBindingProjectFailMarshalJSON.New(in, err)
	}
	if isRoleBindingRoleMissing(err) {
		return ErrRoleBindingProjectRoleNotExist.New(in.RoleName, err)
	}
	if strings.Contains(err.Error(), "alicatalogapis-role_binding_project") {
		return err
	}
	return ErrRoleBindingProjectBadRequest.New(err)
}

// ---------------------------------------------------------------------------------------------------------------------
// Get All
// ---------------------------------------------------------------------------------------------------------------------

type RoleBindingProjectGetAllRequest struct {
	Project string
}

func (c *client) RoleBindingProjectGetAll(ctx context.Context, in *RoleBindingProjectGetAllRequest) (*RoleBinding, error) {
	if in == nil {
		in = new(RoleBindingProjectGetAllRequest)
	}
	if in.Project == "" {
		return nil, ErrRoleBindingProjectMissingProject.New()
	}

	method := http.MethodPost
	path := fmt.Sprintf("api/catalog/v1alpha/projects/%v:getPolicy", in.Project)
	params := url.Values{"principleFormat": []string{"id"}}

	policy := new(RoleBindingPolicy)
	if err := c.sendRequestAndUnmarshal(ctx, method, path, params, nil, nil, http.StatusOK, policy); err != nil {
		return nil, ErrRoleBindingProjectBadRequest.New(err)
	}
	policy.toUserFormat()
	return &RoleBinding{Policy: policy}, nil
}
