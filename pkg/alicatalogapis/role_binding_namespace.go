//nolint:wastedassign
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

type RoleBindingNamespaceCreateRequest struct {
	RoleName            string
	Members             []string
	IgnoreAlreadyExists bool
}

func (c *client) RoleBindingNamespaceCreate(ctx context.Context, in *RoleBindingNamespaceCreateRequest) (*RoleBinding, error) {
	// validation
	if in == nil {
		in = new(RoleBindingNamespaceCreateRequest)
	}
	if in.RoleName == "" {
		return nil, ErrRoleBindingNamespaceMissingRole.New()
	}
	in.Members = slices.GenericsStandardizeSlice(in.Members)
	if len(in.Members) == 0 {
		return nil, ErrRoleBindingNamespaceEmptyMemberToBind.New(in.RoleName)
	}
	binding, err := c.RoleBindingNamespaceGetAll(ctx, &RoleBindingNamespaceGetAllRequest{})
	if err != nil {
		return nil, err
	}
	err = binding.add(in.RoleName, in.Members, in.IgnoreAlreadyExists)
	if err != nil {
		return nil, ErrRoleBindingNamespaceMemberAlreadyExist.New(err)
	}
	binding.Policy.toAliFormat(c.accountID)

	// construct request params
	method := http.MethodPost
	path := fmt.Sprintf("api/catalog/v1alpha/namespaces/%v:setPolicy", c.accountID)
	params := url.Values{"principleFormat": []string{"id"}}
	body, err := json.Marshal(binding)
	if err != nil {
		return nil, ErrRoleBindingNamespaceFailMarshalJSON.New(in, err)
	}

	// request
	policy := new(RoleBindingPolicy)
	defer policy.toUserFormat()
	if err = c.sendRequestAndUnmarshal(ctx, method, path, params, nil, body, http.StatusOK, policy); err != nil {
		if strings.Contains(err.Error(), "role does not exists") {
			return nil, ErrRoleBindingNamespaceRoleNotExist.New(in.RoleName, err)
		}
		return nil, ErrRoleBindingNamespaceBadRequest.New(err)
	}
	return &RoleBinding{Policy: policy}, nil
}

// ---------------------------------------------------------------------------------------------------------------------
// Get
// ---------------------------------------------------------------------------------------------------------------------

type RoleBindingNamespaceGetRequest struct {
	RoleName string
}

func (c *client) RoleBindingNamespaceGet(ctx context.Context, in *RoleBindingNamespaceGetRequest) (*RoleBinding, error) {
	// validation
	if in == nil {
		in = new(RoleBindingNamespaceGetRequest)
	}
	if in.RoleName == "" {
		return nil, ErrRoleBindingNamespaceMissingRole.New()
	}

	// request
	binding, err := c.RoleBindingNamespaceGetAll(ctx, &RoleBindingNamespaceGetAllRequest{})
	if err != nil {
		return nil, err
	}
	err = binding.collect(in.RoleName)
	if err != nil {
		return nil, ErrRoleBindingNamespaceRoleNotExist.New(in.RoleName, err)
	}
	return binding, nil
}

// ---------------------------------------------------------------------------------------------------------------------
// Get All
// ---------------------------------------------------------------------------------------------------------------------

type RoleBindingNamespaceGetAllRequest struct{}

func (c *client) RoleBindingNamespaceGetAll(ctx context.Context, in *RoleBindingNamespaceGetAllRequest) (*RoleBinding, error) {
	// validation
	if in == nil {
		in = new(RoleBindingNamespaceGetAllRequest)
	}

	// construct request params
	method := http.MethodPost
	path := fmt.Sprintf("api/catalog/v1alpha/namespaces/%v:getPolicy", c.accountID)
	params := url.Values{"principleFormat": []string{"id"}}

	// request
	policy := new(RoleBindingPolicy)
	defer policy.toUserFormat()
	if err := c.sendRequestAndUnmarshal(ctx, method, path, params, nil, nil, http.StatusOK, policy); err != nil {
		return nil, ErrRoleBindingNamespaceBadRequest.New(err)
	}
	return &RoleBinding{Policy: policy}, nil
}

// -----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
// Delete
// ---------------------------------------------------------------------------------------------------------------------

type RoleBindingNamespaceDeleteRequest struct {
	RoleName        string
	Members         []string
	IgnoreNotExists bool
}

func (c *client) RoleBindingNamespaceDelete(ctx context.Context, in *RoleBindingNamespaceDeleteRequest) error {
	// validation
	if in == nil {
		in = new(RoleBindingNamespaceDeleteRequest)
	}
	if in.RoleName == "" {
		return ErrRoleBindingNamespaceMissingRole.New()
	}
	in.Members = slices.GenericsStandardizeSlice(in.Members)
	if len(in.Members) == 0 {
		return ErrRoleBindingNamespaceEmptyMemberToUnbind.New(in.RoleName)
	}
	binding, err := c.RoleBindingNamespaceGetAll(ctx, &RoleBindingNamespaceGetAllRequest{})
	if err != nil {
		return err
	}
	err = binding.reduce(in.RoleName, in.Members, in.IgnoreNotExists)
	if err != nil {
		return ErrRoleBindingNamespaceMemberOrRoleNotExist.New(err)
	}
	binding.Policy.toAliFormat(c.accountID)

	// construct request params
	method := http.MethodPost
	path := fmt.Sprintf("api/catalog/v1alpha/namespaces/%v:setPolicy", c.accountID)
	params := url.Values{"principleFormat": []string{"id"}}
	body, err := json.Marshal(binding)
	if err != nil {
		return ErrRoleBindingNamespaceFailMarshalJSON.New(in, err)
	}

	// request
	if err = c.sendRequest(ctx, method, path, params, nil, body, http.StatusOK); err != nil {
		return ErrRoleBindingNamespaceBadRequest.New(err)
	}
	return nil
}
