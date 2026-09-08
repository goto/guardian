package alicatalogapis

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/goto/guardian/pkg/slices"
)

const (
	roleBindingConcurrentModification = "role bindings of this object have been modified"
	roleBindingUpdateMaxAttempts      = 3
	roleBindingRetryBaseDelay         = 50 * time.Millisecond
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
	for attempt := 0; attempt < roleBindingUpdateMaxAttempts; attempt++ {
		// Catalog policy writes use optimistic concurrency. Re-read the complete policy before
		// every retry so a concurrent writer's changes are preserved in the next setPolicy call.
		binding, err := c.RoleBindingProjectGetAll(ctx, &RoleBindingProjectGetAllRequest{
			Project: in.Project,
		})
		if err != nil {
			return nil, err
		}
		binding.add(in.RoleName, in.Members)
		binding.Policy.toAliFormat(c.accountID)

		method := http.MethodPost
		path := fmt.Sprintf("api/catalog/v1alpha/projects/%v:setPolicy", in.Project)
		params := url.Values{"principleFormat": []string{"id"}}
		body, err := json.Marshal(binding)
		if err != nil {
			return nil, ErrRoleBindingProjectFailMarshalJSON.New(in, err)
		}

		policy := new(RoleBindingPolicy)
		err = c.sendRequestAndUnmarshal(ctx, method, path, params, nil, body, http.StatusOK, policy)
		if err == nil {
			policy.toUserFormat()
			return &RoleBinding{Policy: policy}, nil
		}
		if strings.Contains(err.Error(), "role does not exists") {
			return nil, ErrRoleBindingProjectRoleNotExist.New(in.RoleName, err)
		}
		if !isRoleBindingConcurrentModification(err) || attempt == roleBindingUpdateMaxAttempts-1 {
			return nil, ErrRoleBindingProjectBadRequest.New(err)
		}
		if err := waitForRoleBindingRetry(ctx, attempt); err != nil {
			return nil, ErrRoleBindingProjectBadRequest.New(err)
		}
	}

	return nil, ErrRoleBindingProjectBadRequest.New("role binding update attempts exhausted")
}

func isRoleBindingConcurrentModification(err error) bool {
	return err != nil && strings.Contains(strings.ToLower(err.Error()), roleBindingConcurrentModification)
}

func waitForRoleBindingRetry(ctx context.Context, attempt int) error {
	timer := time.NewTimer(roleBindingRetryBaseDelay * time.Duration(1<<attempt))
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
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
