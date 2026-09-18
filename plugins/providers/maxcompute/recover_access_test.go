package maxcompute

import (
	"context"
	"errors"
	"testing"

	pv "github.com/goto/guardian/core/provider"
	"github.com/goto/guardian/domain"
)

func TestProviderRecoverAccessNotApplicable(t *testing.T) {
	t.Parallel()

	p := &provider{}
	g := domain.Grant{
		AccountID: "RAM$1:role/x",
		Resource: &domain.Resource{
			ProviderType: sourceName,
			Type:         resourceTypeProject,
			URN:          "p_mgmc_id_data_access",
		},
	}
	err := p.RecoverAccess(context.Background(), &domain.ProviderConfig{}, g, errors.New("unrelated failure"))
	if !errors.Is(err, pv.ErrRecoverNotApplicable) {
		t.Fatalf("got %v want ErrRecoverNotApplicable", err)
	}
}
