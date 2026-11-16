package grant_test

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	guardianv1beta1 "github.com/goto/guardian/api/proto/gotocompany/guardian/v1beta1"
	"github.com/goto/guardian/core/grant"
	"github.com/goto/guardian/domain"
	"github.com/goto/guardian/internal/store/postgres"
	"github.com/goto/guardian/pkg/log"
	"github.com/goto/guardian/pkg/postgrestest"
	"github.com/stretchr/testify/require"
)

func TestSmartInactiveCrossRequestorWithPostgres(t *testing.T) {
	if testing.Short() {
		t.Skip("requires owned disposable PostgreSQL")
	}
	store, pool, resource, err := postgrestest.NewTestStore(log.NewNoop())
	require.NoError(t, err)
	db, err := store.DB().DB()
	require.NoError(t, err)
	defer func() { _ = db.Close(); require.NoError(t, postgrestest.PurgeTestDocker(pool, resource)) }()
	ctx := context.Background()
	rid := uuid.NewString()
	require.NoError(t, store.DB().Exec(`INSERT INTO providers(type,urn) VALUES ('guardian','fixture')`).Error)
	require.NoError(t, store.DB().Exec(`INSERT INTO resources(id,provider_type,provider_urn,type,urn,name,global_urn,details,labels,is_deleted)
 VALUES (?,'guardian','fixture','package','fixture-package','Fixture package','guardian/fixture/package','{}','{}',false)`, rid).Error)
	oldSelf, oldOther, expired := uuid.NewString(), uuid.NewString(), uuid.NewString()
	for _, g := range []struct{ id, account, role, status, owner string }{
		{oldSelf, "Person@example.test", "admin", "inactive", "requestor@example.test"},
		{oldOther, "other@example.test", "member", "inactive", "requestor@example.test"},
		{expired, "expired@example.test", "member", "inactive", "requestor@example.test"},
		{uuid.NewString(), "person@example.test", "admin", "active", "new-admin@example.test"},
		{uuid.NewString(), "other@example.test", "member", "active", "new-admin@example.test"},
	} {
		require.NoError(t, store.DB().Exec(`INSERT INTO grants(id,account_id,account_type,resource_id,role,permissions,status,owner,group_id,group_type,created_at,updated_at,expiration_date)
 VALUES (?,?,'user',?,?,ARRAY[?]::text[],?,?,?,'package_user',NOW(),NOW(),?)`, g.id, g.account, rid, g.role, g.role, g.status, g.owner, rid, time.Now().Add(90*24*time.Hour)).Error)
	}
	repo := postgres.NewGrantRepository(store.DB())
	svc := grant.NewService(grant.ServiceDeps{Repository: repo, Logger: log.NewNoop()})
	filter := domain.ListGrantsFilter{Owner: "requestor@example.test", Statuses: []string{"inactive"}, ResourceIDs: []string{rid}, UserInactiveGrantPolicy: guardianv1beta1.ListUserGrantsRequest_INACTIVE_GRANT_POLICY_SMART}
	excluded, err := svc.GenerateUserExcludedGrantIDsForSmartInactiveGrants(ctx, filter)
	require.NoError(t, err)
	require.ElementsMatch(t, []string{oldSelf, oldOther}, excluded)
	filter.NotIDs = excluded
	remaining, err := repo.List(ctx, filter)
	require.NoError(t, err)
	require.Len(t, remaining, 1)
	require.Equal(t, expired, remaining[0].ID)
	// Include-all remains history, and the caller cannot gain rows from the other owner.
	filter.NotIDs = nil
	filter.UserInactiveGrantPolicy = guardianv1beta1.ListUserGrantsRequest_INACTIVE_GRANT_POLICY_INCLUDE_ALL
	excluded, err = svc.GenerateUserExcludedGrantIDsForSmartInactiveGrants(ctx, filter)
	require.NoError(t, err)
	require.Empty(t, excluded)
	history, err := repo.List(ctx, filter)
	require.NoError(t, err)
	require.Len(t, history, 3)
}
