package alicloud_ram

import (
	"context"
	"testing"

	"github.com/goto/guardian/domain"
	"github.com/stretchr/testify/assert"
)

func TestProviderGetAccountTypes(t *testing.T) {
	p := &Provider{}

	assert.Equal(t, []string{AccountTypeRamUser, AccountTypeRamRole, domain.AccountTypePackage}, p.GetAccountTypes())
}

func TestProviderGrantAccessNoOpForPackageAccount(t *testing.T) {
	p := &Provider{}

	err := p.GrantAccess(context.Background(), nil, domain.Grant{
		AccountID:   "pkg-1",
		AccountType: domain.AccountTypePackage,
		Resource: &domain.Resource{
			Type: ResourceTypeAccount,
			URN:  "5139931567401769",
		},
	})

	assert.NoError(t, err)
}

func TestProviderRevokeAccessNoOpForPackageAccount(t *testing.T) {
	p := &Provider{}

	err := p.RevokeAccess(context.Background(), nil, domain.Grant{
		AccountID:   "pkg-1",
		AccountType: domain.AccountTypePackage,
		Resource: &domain.Resource{
			Type: ResourceTypeAccount,
			URN:  "5139931567401769",
		},
	})

	assert.NoError(t, err)
}
