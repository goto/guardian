package providers

import (
	"context"

	"github.com/goto/guardian/domain"
)

type Client interface {
	GetType() string
	CreateConfig(*domain.ProviderConfig) error
	GrantAccess(context.Context, *domain.ProviderConfig, domain.Grant) error
	RevokeAccess(context.Context, *domain.ProviderConfig, domain.Grant) error
	GetRoles(pc *domain.ProviderConfig, resourceType string) ([]*domain.Role, error)
	GetAccountTypes() []string
	ListAccess(context.Context, domain.ProviderConfig, []*domain.Resource) (domain.MapResourceAccess, error)
	ListAccessForUsers(context.Context, domain.ProviderConfig, []*domain.Resource, []string) (domain.MapResourceAccess, error)
}

// AccessRecoverer is an optional provider capability used when GrantAccess fails
// and the provider can heal prerequisites (e.g. missing project membership) from
// the failing grant and the provider error alone.
type AccessRecoverer interface {
	RecoverAccess(ctx context.Context, pc *domain.ProviderConfig, g domain.Grant, cause error) error
}

type PermissionManager interface {
	GetPermissions(p *domain.ProviderConfig, resourceType, role string) ([]interface{}, error)
}
