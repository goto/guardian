package oss

import (
	"context"
	"testing"

	"github.com/goto/guardian/domain"
	"github.com/stretchr/testify/assert"
)

func TestProviderGetAccountTypes(t *testing.T) {
	p := &provider{}

	assert.Equal(t, []string{AccountTypeRAMUser, AccountTypeRAMRole, domain.AccountTypePackage}, p.GetAccountTypes())
}

func TestProviderGrantAccessNoOpForPackageAccount(t *testing.T) {
	p := &provider{}

	err := p.GrantAccess(context.Background(), nil, domain.Grant{
		AccountID:   "pkg-1",
		AccountType: domain.AccountTypePackage,
		Resource: &domain.Resource{
			Type: resourceTypeBucket,
			URN:  "bucket-a",
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
			Type: resourceTypeBucket,
			URN:  "bucket-a",
		},
	})

	assert.NoError(t, err)
}
