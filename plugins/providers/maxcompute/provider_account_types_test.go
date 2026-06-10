package maxcompute

import (
	"context"
	"testing"

	"github.com/goto/guardian/domain"
	"github.com/stretchr/testify/assert"
)

func TestProviderGetAccountTypes(t *testing.T) {
	p := &provider{}

	assert.Equal(t, []string{accountTypeRAMUser, accountTypeRAMRole, domain.AccountTypePackage}, p.GetAccountTypes())
}

func TestProviderGrantAccessNoOpForPackageAccount(t *testing.T) {
	p := &provider{}

	err := p.GrantAccess(context.Background(), nil, domain.Grant{
		AccountID:   "pkg-1",
		AccountType: domain.AccountTypePackage,
		Resource: &domain.Resource{
			ProviderType: sourceName,
			Type:         resourceTypeProject,
			URN:          "project_a",
		},
	})

	assert.NoError(t, err)
}

func TestProviderRevokeAccessNoOpForPackageAccount(t *testing.T) {
	p := &provider{}

	err := p.RevokeAccess(context.Background(), nil, domain.Grant{
		AccountID:   "pkg-1",
		AccountType: domain.AccountTypePackage,
		Resource: &domain.Resource{
			ProviderType: sourceName,
			Type:         resourceTypeProject,
			URN:          "project_a",
		},
	})

	assert.NoError(t, err)
}

func TestProviderDependencyGrantsSkipForPackageAccount(t *testing.T) {
	p := &provider{}

	grants, err := p.GetDependencyGrants(context.Background(), domain.Provider{}, domain.Grant{
		AccountID:   "pkg-1",
		AccountType: domain.AccountTypePackage,
		Resource: &domain.Resource{
			ProviderType: sourceName,
			Type:         resourceTypeTable,
			URN:          "project_a.schema_a",
		},
	})

	assert.NoError(t, err)
	assert.Nil(t, grants)
}
