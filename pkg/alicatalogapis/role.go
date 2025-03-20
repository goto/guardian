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

type RoleCreateRequest struct {
	RoleName    string   `json:"roleName"`
	Description string   `json:"description"`
	Permissions []string `json:"includedPermissions"`
}

func (c *client) RoleCreate(ctx context.Context, in *RoleCreateRequest) (*Role, error) {
	// validation
	if in == nil {
		in = new(RoleCreateRequest)
	}
	if in.RoleName == "" {
		return nil, ErrRoleMissingRole.New()
	}
	in.Permissions = slices.GenericsStandardizeSlice(in.Permissions)

	// construct request params
	method := http.MethodPost
	path := fmt.Sprintf("api/catalog/v1alpha/namespaces/%v/roles", c.accountID)
	body, err := json.Marshal(in)
	if err != nil {
		return nil, ErrRoleFailMarshalJSON.New(in, err)
	}

	// request
	out := new(Role)
	if err = c.sendRequestAndUnmarshal(ctx, method, path, nil, nil, body, http.StatusOK, out); err != nil {
		if strings.Contains(err.Error(), "AlreadyExists") {
			return nil, ErrRoleAlreadyExist.New(in.RoleName, err)
		}
		return nil, ErrRoleBadRequest.New(err)
	}
	out.Permissions = slices.GenericsStandardizeSlice(out.Permissions)
	return out, nil
}

// ---------------------------------------------------------------------------------------------------------------------
// Get
// ---------------------------------------------------------------------------------------------------------------------

type RoleGetRequest struct {
	RoleName string
}

func (c *client) RoleGet(ctx context.Context, in *RoleGetRequest) (*Role, error) {
	// validation
	if in == nil {
		in = new(RoleGetRequest)
	}
	if in.RoleName == "" {
		return nil, ErrRoleMissingRole.New()
	}

	// construct request params
	method := http.MethodGet
	path := fmt.Sprintf("api/catalog/v1alpha/namespaces/%v/roles/%v", c.accountID, in.RoleName)

	// request
	out := new(Role)
	if err := c.sendRequestAndUnmarshal(ctx, method, path, nil, nil, nil, http.StatusOK, out); err != nil {
		if strings.Contains(err.Error(), "NotFound") {
			return nil, ErrRoleNotExist.New(in.RoleName, err)
		}
		return nil, ErrRoleBadRequest.New(err)
	}
	out.Permissions = slices.GenericsStandardizeSlice(out.Permissions)
	return out, nil
}

// ---------------------------------------------------------------------------------------------------------------------
// Get All
// ---------------------------------------------------------------------------------------------------------------------

type RoleGetAllRequest struct {
	WithPermissions  bool
	WithDeletedRoles bool
}

func (c *client) RoleGetAll(ctx context.Context, in *RoleGetAllRequest) ([]*Role, error) {
	// validation
	if in == nil {
		in = new(RoleGetAllRequest)
	}
	view := "BASIC"
	if in.WithPermissions {
		view = "FULL"
	}
	showDeleted := strings.ToLower(fmt.Sprint(in.WithDeletedRoles))

	// construct request params
	method := http.MethodGet
	path := fmt.Sprintf("api/catalog/v1alpha/namespaces/%v/roles", c.accountID)
	params := url.Values{
		"pageSize":    []string{"1000"}, // 1000 (max)
		"view":        []string{view},
		"showDeleted": []string{showDeleted},
	}

	// request
	type respRawStruct struct {
		NextPageToken string  `json:"nextPageToken"`
		Roles         []*Role `json:"roles"`
	}
	var out []*Role
	for {
		var done bool
		if err := func() error {
			respRaw := &respRawStruct{}
			if err := c.sendRequestAndUnmarshal(ctx, method, path, params, nil, nil, http.StatusOK, respRaw); err != nil {
				return ErrRoleBadRequest.New(err)
			}
			out = append(out, respRaw.Roles...)
			if respRaw.NextPageToken == "" {
				done = true
				return nil
			}
			params.Set("pageToken", respRaw.NextPageToken)
			return nil
		}(); err != nil {
			return nil, err
		}
		if done {
			break
		}
	}
	for i := range out {
		out[i].Permissions = slices.GenericsStandardizeSlice(out[i].Permissions)
	}
	return out, nil
}

// ---------------------------------------------------------------------------------------------------------------------
// Update
// ---------------------------------------------------------------------------------------------------------------------

type RoleUpdateRequest struct {
	ExecuteUpdateOnEmptyField bool     `json:"-"`
	RoleName                  string   `json:"roleName"`
	Description               string   `json:"description"`
	Permissions               []string `json:"includedPermissions"`
}

func (c *client) RoleUpdate(ctx context.Context, in *RoleUpdateRequest) (*Role, error) {
	// validation
	if in == nil {
		in = new(RoleUpdateRequest)
	}
	if in.RoleName == "" {
		return nil, ErrRoleMissingRole.New()
	}
	in.Permissions = slices.GenericsStandardizeSlice(in.Permissions)

	// fetch origin values
	origin, err := c.RoleGet(ctx, &RoleGetRequest{RoleName: in.RoleName})
	if err != nil {
		return nil, err
	}
	origin.Permissions = slices.GenericsStandardizeSlice(origin.Permissions)

	// request
	var out *Role
	if in.Description != origin.Description && (in.Description != "" || in.ExecuteUpdateOnEmptyField) {
		out, err = c.roleUpdate(ctx, "description", in)
	}
	if !slices.GenericsIsSliceEqual(in.Permissions, origin.Permissions) && (len(in.Permissions) > 0 || in.ExecuteUpdateOnEmptyField) {
		out, err = c.roleUpdate(ctx, "includedPermissions", in)
	}
	if err != nil {
		return nil, err
	}
	if out == nil {
		out = origin
	}
	out.Permissions = slices.GenericsStandardizeSlice(out.Permissions)
	return out, nil
}

func (c *client) roleUpdate(ctx context.Context, fieldToUpdate string, in *RoleUpdateRequest) (*Role, error) {
	// construct request params
	method := http.MethodPatch
	path := fmt.Sprintf("api/catalog/v1alpha/namespaces/%v/roles/%v", c.accountID, in.RoleName)
	params := url.Values{"updateMask": []string{fieldToUpdate}}
	body, err := json.Marshal(in)
	if err != nil {
		return nil, ErrRoleFailMarshalJSON.New(in, err)
	}

	// request
	out := new(Role)
	if err = c.sendRequestAndUnmarshal(ctx, method, path, params, nil, body, http.StatusOK, out); err != nil {
		if strings.Contains(err.Error(), "NotFound") {
			return nil, ErrRoleNotExist.New(in.RoleName, err)
		}
		return nil, ErrRoleBadRequest.New(err)
	}
	out.Permissions = slices.GenericsStandardizeSlice(out.Permissions)
	return out, nil
}

// ---------------------------------------------------------------------------------------------------------------------
// Delete
// ---------------------------------------------------------------------------------------------------------------------

type RoleDeleteRequest struct {
	RoleName string
}

func (c *client) RoleDelete(ctx context.Context, in *RoleDeleteRequest) error {
	// validation
	if in == nil {
		in = new(RoleDeleteRequest)
	}
	if in.RoleName == "" {
		return ErrRoleMissingRole.New()
	}

	// construct request params
	method := http.MethodDelete
	path := fmt.Sprintf("api/catalog/v1alpha/namespaces/%v/roles/%v", c.accountID, in.RoleName)

	// request
	if err := c.sendRequest(ctx, method, path, nil, nil, nil, http.StatusOK); err != nil {
		if strings.Contains(err.Error(), "NotFound") {
			return ErrRoleNotExist.New(in.RoleName, err)
		}
		return ErrRoleBadRequest.New(err)
	}
	return nil
}
