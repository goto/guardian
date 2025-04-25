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

type RoleBindingProjectCreateRequest struct {
	Project  string
	RoleName string
	Members  []string
}

func (c *client) RoleBindingProjectCreate(ctx context.Context, in *RoleBindingProjectCreateRequest) (*RoleBinding, error) {
	// validation
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
	binding, err := c.RoleBindingProjectGetAll(ctx, &RoleBindingProjectGetAllRequest{
		Project: in.Project,
	})
	if err != nil {
		return nil, err
	}
	binding.add(in.RoleName, in.Members)
	binding.Policy.toAliFormat(c.accountID)

	// construct request params
	method := http.MethodPost
	path := fmt.Sprintf("api/catalog/v1alpha/projects/%v:setPolicy", in.Project)
	params := url.Values{"principleFormat": []string{"id"}}
	body, err := json.Marshal(binding)
	if err != nil {
		return nil, ErrRoleBindingProjectFailMarshalJSON.New(in, err)
	}

	// request
	policy := new(RoleBindingPolicy)
	if err = c.sendRequestAndUnmarshal(ctx, method, path, params, nil, body, http.StatusOK, policy); err != nil {
		if strings.Contains(err.Error(), "role does not exists") {
			return nil, ErrRoleBindingProjectRoleNotExist.New(in.RoleName, err)
		}
		return nil, ErrRoleBindingProjectBadRequest.New(err)
	}
	policy.toUserFormat()
	return &RoleBinding{Policy: policy}, nil
}

// ---------------------------------------------------------------------------------------------------------------------
// Get All
// ---------------------------------------------------------------------------------------------------------------------

type RoleBindingProjectGetAllRequest struct {
	Project string
}

func (c *client) RoleBindingProjectGetAll(ctx context.Context, in *RoleBindingProjectGetAllRequest) (*RoleBinding, error) {
	// validation
	if in == nil {
		in = new(RoleBindingProjectGetAllRequest)
	}
	if in.Project == "" {
		return nil, ErrRoleBindingProjectMissingProject.New()
	}

	// construct request params
	method := http.MethodPost
	path := fmt.Sprintf("api/catalog/v1alpha/projects/%v:getPolicy", in.Project)
	params := url.Values{"principleFormat": []string{"id"}}

	// request
	policy := new(RoleBindingPolicy)
	if err := c.sendRequestAndUnmarshal(ctx, method, path, params, nil, nil, http.StatusOK, policy); err != nil {
		return nil, ErrRoleBindingProjectBadRequest.New(err)
	}
	policy.toUserFormat()
	return &RoleBinding{Policy: policy}, nil
}
