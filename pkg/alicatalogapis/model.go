package alicatalogapis

import (
	"fmt"
	"path"

	"github.com/goto/guardian/pkg/slices"
)

// ---------------------------------------------------------------------------------------------------------------------
// Role
// ---------------------------------------------------------------------------------------------------------------------

type Role struct {
	RoleName    string   `json:"roleName"` // ex: datawriter
	RoleURN     string   `json:"name"`     // ex: namespaces/5123xxx/roles/datawriter
	Description string   `json:"description"`
	Permissions []string `json:"includedPermissions,omitempty"` // ex: ["ListSchema", "GetSchema"]
	Deleted     bool     `json:"deleted"`
}

// ---------------------------------------------------------------------------------------------------------------------
// Role Binding
// ---------------------------------------------------------------------------------------------------------------------

type RoleBinding struct {
	Policy *RoleBindingPolicy `json:"policy"`
}

type RoleBindingPolicy struct {
	ETag     string                       `json:"etag"`
	Bindings []*RoleBindingPolicyBindings `json:"bindings"`
}

type RoleBindingPolicyBindings struct {
	Role    string   `json:"role"`
	Members []string `json:"members"`
}

type RoleBindingRaw map[string][]string

func (rb *RoleBindingPolicy) toUserFormat() {
	for _, binding := range rb.Bindings {
		binding.Role = path.Base(binding.Role)
	}
}

func (rb *RoleBindingPolicy) toAliFormat(accountID string) {
	for _, binding := range rb.Bindings {
		aliBindingRoleFormat := path.Join("namespaces", accountID, "roles", path.Base(binding.Role))
		if binding.Role == aliBindingRoleFormat {
			continue
		}
		binding.Role = path.Join("namespaces", accountID, "roles", binding.Role)
	}
}

func (rb *RoleBinding) toRaw() RoleBindingRaw {
	if rb.Policy == nil {
		rb.Policy = new(RoleBindingPolicy)
	}
	if rb.Policy.Bindings == nil {
		rb.Policy.Bindings = make([]*RoleBindingPolicyBindings, 0)
	}
	out := make(RoleBindingRaw)
	for _, binding := range rb.Policy.Bindings {
		if members, ok := out[binding.Role]; !ok {
			out[binding.Role] = slices.GenericsStandardizeSlice(binding.Members)
		} else {
			out[binding.Role] = slices.GenericsStandardizeSlice(append(members, binding.Members...))
		}
	}
	return out
}

func (rb *RoleBinding) fromRaw(in RoleBindingRaw) {
	if rb.Policy == nil {
		rb.Policy = new(RoleBindingPolicy)
	}
	rb.Policy.Bindings = make([]*RoleBindingPolicyBindings, 0)
	for role, members := range in {
		members = slices.GenericsStandardizeSlice(members)
		if len(members) == 0 {
			continue
		}
		rb.Policy.Bindings = append(rb.Policy.Bindings, &RoleBindingPolicyBindings{Role: role, Members: members})
	}
}

func (rb *RoleBinding) add(roleName string, membersToAdd []string, ignoreAlreadyExist bool) error {
	membersToAdd = slices.GenericsStandardizeSlice(membersToAdd)
	raw := rb.toRaw()
	members, ok := raw[roleName]
	if !ok {
		raw[roleName] = membersToAdd
	} else {
		if !ignoreAlreadyExist {
			validator := make(map[string]struct{})
			for _, member := range members {
				validator[member] = struct{}{}
			}
			for _, memberToAdd := range membersToAdd {
				if _, ok = validator[memberToAdd]; ok {
					return fmt.Errorf("member '%s' on role '%s' is already exist on current active bindings", memberToAdd, roleName)
				}
			}
		}
		raw[roleName] = append(members, membersToAdd...)
	}
	rb.fromRaw(raw)
	return nil
}

func (rb *RoleBinding) reduce(roleName string, membersToRemove []string, ignoreNotExist bool) error {
	membersToRemove = slices.GenericsStandardizeSlice(membersToRemove)
	raw := rb.toRaw()
	members, ok := raw[roleName]
	if !ok && !ignoreNotExist {
		return fmt.Errorf("role '%s' is does not exist on current active bindings", roleName)
	} else if ok {
		validator := make(map[string]struct{})
		for _, member := range members {
			validator[member] = struct{}{}
		}
		for _, memberToRemove := range membersToRemove {
			if _, ok = validator[memberToRemove]; !ok {
				if ignoreNotExist {
					continue
				}
				return fmt.Errorf("member '%s' on role '%s' is does not exist on current active bindings", memberToRemove, roleName)
			}
			delete(validator, memberToRemove)
		}
		members = make([]string, len(validator))
		for member := range validator {
			members = append(members, member)
		}
		raw[roleName] = members
	}
	rb.fromRaw(raw)
	return nil
}

func (rb *RoleBinding) collect(roleName string) error {
	raw := rb.toRaw()
	members, ok := raw[roleName]
	if !ok {
		return fmt.Errorf("role '%s' is does not exist on current active bindings", roleName)
	}
	rb.fromRaw(map[string][]string{roleName: members})
	return nil
}
