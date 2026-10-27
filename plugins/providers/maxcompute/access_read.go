package maxcompute

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/goto/guardian/domain"
	"github.com/goto/guardian/pkg/alicatalogapis"
)

var errInvalidAccessResponse = errors.New("invalid MaxCompute access response")

func (s *accessSession) projectRoles(ctx context.Context, principal string) ([]string, error) {
	raw, err := s.query(ctx, fmt.Sprintf("SHOW GRANTS FOR `%s`;", principal))
	if err != nil {
		return nil, err
	}
	var shape map[string]json.RawMessage
	if err := json.Unmarshal([]byte(raw), &shape); err != nil || shape == nil {
		return nil, fmt.Errorf("%w: project roles", errInvalidAccessResponse)
	}
	recognized := len(shape) == 0
	for _, key := range []string{"Roles", "ACL", "POLICY", "SuperPrivs", "ProjectOwner", "ObjectCreator"} {
		if _, ok := shape[key]; ok {
			recognized = true
		}
	}
	if !recognized {
		return nil, fmt.Errorf("%w: unknown project grants format", errInvalidAccessResponse)
	}
	var data *struct{ Roles []string }
	if err := json.Unmarshal([]byte(raw), &data); err != nil || data == nil {
		return nil, fmt.Errorf("%w: project roles", errInvalidAccessResponse)
	}
	return data.Roles, nil
}

func (s *accessSession) read(ctx context.Context, t accessTarget, grant bool) (map[string]bool, error) {
	state := make(map[string]bool)
	switch t.resourceType {
	case resourceTypeProject:
		raw, err := s.query(ctx, "LIST USERS;")
		if err != nil {
			if !grant && missingAccessObject(err) {
				return state, nil
			}
			return nil, err
		}
		var users []string
		if err := json.Unmarshal([]byte(raw), &users); err != nil || users == nil {
			return nil, fmt.Errorf("%w: project users", errInvalidAccessResponse)
		}
		for _, user := range users {
			if user == t.principal {
				state[projectPermissionMember] = true
			}
		}
		// Do not infer membership from a successful SHOW GRANTS query.
		if !state[projectPermissionMember] {
			return state, nil
		}
		if len(t.permissions) == 1 && t.permissions[0] == projectPermissionMember {
			return state, nil
		}
		roles, err := s.projectRoles(ctx, t.principal)
		if err != nil {
			return nil, err
		}
		for _, role := range roles {
			state[role] = true
		}
	case resourceTypeSchema:
		binding, err := s.catalog.RoleBindingSchemaGetAll(ctx, &alicatalogapis.RoleBindingSchemaGetAllRequest{Project: t.project, Schema: t.schema})
		if err != nil {
			if !grant && missingAccessObject(err) {
				return state, nil
			}
			return nil, err
		}
		state, err = bindingRoles(binding, t.principal)
		if err != nil {
			return nil, err
		}
		if grant && t.defaultRole != "" {
			binding, err := s.catalog.RoleBindingProjectGetAll(ctx, &alicatalogapis.RoleBindingProjectGetAllRequest{Project: t.project})
			if err != nil {
				return nil, err
			}
			roles, err := bindingRoles(binding, t.principal)
			if err != nil {
				return nil, err
			}
			state[defaultRoleKey(t.defaultRole)] = roles[t.defaultRole]
		}
	case resourceTypeTable:
		raw, err := s.query(ctx, fmt.Sprintf("SHOW GRANTS ON TABLE `%s`.`%s`.`%s`;", t.project, t.schema, t.table))
		if err != nil {
			if !grant && missingAccessObject(err) {
				return state, nil
			}
			return nil, err
		}
		entries, err := parseTableAccess(raw, t.principal)
		if err != nil {
			return nil, err
		}
		for _, entry := range entries {
			state[strings.ToLower(entry.Permission)] = true
		}
		// All covers ordinary table ACL actions. Cold-storage actions remain
		// explicit: do not assume All implies tenant-specific cold permissions.
		if state["all"] {
			for _, action := range []string{"describe", "select", "alter", "update", "drop", "showhistory"} {
				state[action] = true
			}
		}
		// REVOKE All must leave no direct ACL actions for this principal, even
		// when MaxCompute returns individual actions rather than the All token.
		if !grant {
			for _, permission := range t.permissions {
				if permission == "all" {
					state["all"] = len(entries) > 0
				}
			}
		}
	}
	return state, nil
}

func bindingRoles(binding *alicatalogapis.RoleBinding, principal string) (map[string]bool, error) {
	if binding == nil || binding.Policy == nil {
		return nil, fmt.Errorf("%w: missing CatalogAPI policy", errInvalidAccessResponse)
	}
	roles := make(map[string]bool)
	for _, b := range binding.Policy.Bindings {
		if b == nil || b.Role == "" {
			return nil, fmt.Errorf("%w: invalid CatalogAPI binding", errInvalidAccessResponse)
		}
		for _, member := range b.Members {
			if member == principal {
				roles[b.Role] = true
			}
		}
	}
	return roles, nil
}

func parseTableAccess(raw string, users ...string) ([]domain.AccessEntry, error) {
	var data struct {
		ACL map[string][]struct {
			Action    []string
			Effect    string
			Principal []string
		}
	}
	if err := json.Unmarshal([]byte(raw), &data); err != nil || data.ACL == nil {
		return nil, fmt.Errorf("%w: missing or malformed table ACL", errInvalidAccessResponse)
	}
	for key := range data.ACL {
		if key != "" {
			return nil, fmt.Errorf("%w: unknown table ACL scope", errInvalidAccessResponse)
		}
	}
	filter := make(map[string]bool, len(users))
	for _, user := range users {
		filter[user] = true
	}
	var entries []domain.AccessEntry
	// Only direct ACL entries belong to the assignments this provider manages.
	for _, entry := range data.ACL[""] {
		if strings.EqualFold(entry.Effect, "Deny") {
			continue
		}
		if entry.Effect != "" && !strings.EqualFold(entry.Effect, "Allow") {
			return nil, fmt.Errorf("%w: unknown table ACL effect", errInvalidAccessResponse)
		}
		if len(entry.Action) == 0 || len(entry.Principal) == 0 {
			return nil, fmt.Errorf("%w: incomplete table ACL entry", errInvalidAccessResponse)
		}
		for _, principal := range entry.Principal {
			account, ok := strings.CutPrefix(principal, "user/")
			if !ok {
				if strings.HasPrefix(principal, "role/") {
					continue
				}
				return nil, fmt.Errorf("%w: unknown table principal format", errInvalidAccessResponse)
			}
			if strings.Contains(account, "(") && !strings.HasSuffix(account, ")") {
				return nil, fmt.Errorf("%w: malformed table principal suffix", errInvalidAccessResponse)
			}
			account, _, _ = strings.Cut(account, "(")
			if !safeAccessIdentifier(account) {
				return nil, fmt.Errorf("%w: invalid table principal", errInvalidAccessResponse)
			}
			if len(users) > 0 && !filter[account] {
				continue
			}
			for _, action := range entry.Action {
				if action == "" {
					return nil, fmt.Errorf("%w: empty table action", errInvalidAccessResponse)
				}
				entries = append(entries, domain.AccessEntry{AccountID: account, AccountType: inferAccountType(account), Permission: strings.ToUpper(action)})
			}
		}
	}
	return entries, nil
}
