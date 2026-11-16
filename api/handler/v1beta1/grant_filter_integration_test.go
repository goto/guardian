package v1beta1_test

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	v1beta1 "github.com/goto/guardian/api/handler/v1beta1"
	guardianv1beta1 "github.com/goto/guardian/api/proto/gotocompany/guardian/v1beta1"
	"github.com/goto/guardian/core/grant"
	"github.com/goto/guardian/internal/store/postgres"
	"github.com/goto/guardian/pkg/log"
	"github.com/goto/guardian/pkg/postgrestest"
	"github.com/grpc-ecosystem/grpc-gateway/v2/runtime"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/encoding/protojson"
)

// Exercise the real HTTP query decoder, handler, service, repository and response
// adapter with the exact My Resources filter. All records are synthetic/local.
func TestMyResourcesExactInactiveFilterWithPostgres(t *testing.T) {
	if testing.Short() {
		t.Skip("requires owned disposable PostgreSQL")
	}
	store, pool, resource, err := postgrestest.NewTestStore(log.NewNoop())
	require.NoError(t, err)
	db, err := store.DB().DB()
	require.NoError(t, err)
	defer func() { _ = db.Close(); require.NoError(t, postgrestest.PurgeTestDocker(pool, resource)) }()

	makeResource := func(provider, urn, typ string) string {
		t.Helper()
		id := uuid.NewString()
		require.NoError(t, store.DB().Exec(`INSERT INTO providers(type,urn) VALUES (?,?) ON CONFLICT DO NOTHING`, provider, urn).Error)
		require.NoError(t, store.DB().Exec(`INSERT INTO resources(id,provider_type,provider_urn,type,urn,name,global_urn,details,labels,is_deleted)
 VALUES (?,?,?,?,?,'Fixture resource',?,'{}','{}',false)`, id, provider, urn, typ, id, "fixture/"+id).Error)
		return id
	}
	packageID := makeResource("guardian", "fixture", "package")
	caller := "requestor@example.test"
	base := time.Date(2026, 8, 1, 0, 0, 0, 0, time.UTC)
	makeAppeal := func(rid, account, role, status, owner string) string {
		t.Helper()
		id := uuid.NewString()
		require.NoError(t, store.DB().Exec(`INSERT INTO appeals(id,resource_id,account_id,account_type,role,status,created_by,options,details,labels,permissions,created_at,updated_at)
 VALUES (?,?,?,'user',?,?,?,'{"duration":"90d"}','{}','{}',ARRAY[?]::text[],?,?)`, id, rid, account, role, status, owner, role, base, base).Error)
		return id
	}
	makeGrant := func(rid, account, role, status, owner string, updated time.Time, hasAppeal bool) string {
		t.Helper()
		id := uuid.NewString()
		var appealID interface{}
		if hasAppeal {
			appealID = makeAppeal(rid, account, role, "approved", owner)
		}
		expires := base.Add(90 * 24 * time.Hour)
		if status == "active" {
			expires = time.Now().Add(90 * 24 * time.Hour)
		}
		require.NoError(t, store.DB().Exec(`INSERT INTO grants(id,resource_id,account_id,account_type,role,permissions,status,owner,group_id,group_type,appeal_id,created_at,updated_at,expiration_date)
 VALUES (?,?,?,'user',?,ARRAY[?]::text[],?,?,?,'package_user',?,?,?,?)`, id, rid, account, role, role, status, owner, rid, appealID, base, updated, expires).Error)
		return id
	}
	// More than a page of legitimate inactive history, including an account
	// whose active grant is for a different role and must not hide this row.
	wantIDs := make([]string, 55)
	for i := range wantIDs {
		wantIDs[i] = makeGrant(packageID, fmt.Sprintf("person%02d@example.test", i), "member", "inactive", caller, base.Add(time.Duration(i)*time.Minute), true)
	}
	superseded := makeGrant(packageID, "person00@example.test", "admin", "inactive", caller, base.Add(time.Hour), true)
	makeGrant(packageID, "person00@example.test", "admin", "active", "other-admin@example.test", base.Add(100*24*time.Hour), true)
	makeGrant(packageID, "already-active@example.test", "member", "active", caller, base, true)
	makeGrant(packageID, "foreign-history@example.test", "member", "inactive", "other-admin@example.test", base, true)
	makeGrant(packageID, "no-appeal@example.test", "member", "inactive", caller, base, false)
	for _, urn := range []string{"litmus-production_custom-http", "litmus-staging_custom-http", "litmus-sandbox_custom-http"} {
		makeGrant(makeResource("guardian", urn, "package"), "excluded@example.test", "member", "inactive", caller, base, true)
	}
	makeGrant(makeResource("maxcompute", "fixture", "package"), "provider@example.test", "member", "inactive", caller, base, true)
	makeGrant(makeResource("guardian", "fixture", "project"), "type@example.test", "member", "inactive", caller, base, true)
	pendingID := makeAppeal(packageID, "person54@example.test", "member", "pending", "another-requestor@example.test")

	svc := grant.NewService(grant.ServiceDeps{Repository: postgres.NewGrantRepository(store.DB()), Logger: log.NewNoop()})
	svc.SetAppealService(postgres.NewAppealRepository(store.DB()))
	server := v1beta1.NewGRPCServer(nil, nil, nil, nil, nil, nil, svc, v1beta1.NewAdapter(), authEmailTestContextKey{}, log.NewNoop())
	mux := runtime.NewServeMux()
	require.NoError(t, guardianv1beta1.RegisterGuardianServiceHandlerServer(context.Background(), mux, server))
	query := "size=50&offset=0&statuses=inactive&provider_types=guardian&resource_types=package&inactive_grant_policy=2&order_by=status&order_by=updated_at%3Adesc&with_pending_appeal=true&exclude_empty_appeal=true&not_provider_urns=litmus-production_custom-http&not_provider_urns=litmus-staging_custom-http&not_provider_urns=litmus-sandbox_custom-http"
	read := func(q string) *guardianv1beta1.ListUserGrantsResponse {
		t.Helper()
		request := httptest.NewRequest(http.MethodGet, "/v1beta1/me/grants?"+q, nil)
		request = request.WithContext(context.WithValue(request.Context(), authEmailTestContextKey{}, caller))
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, request)
		require.Equal(t, http.StatusOK, w.Code, w.Body.String())
		var response guardianv1beta1.ListUserGrantsResponse
		require.NoError(t, protojson.Unmarshal(w.Body.Bytes(), &response))
		return &response
	}
	page := read(query)
	require.EqualValues(t, 55, page.Total)
	require.Len(t, page.Grants, 50)
	for i, g := range page.Grants {
		require.Equal(t, wantIDs[54-i], g.Id, "sorting/filtering changed")
		require.Equal(t, "inactive", g.Status)
	}
	require.Equal(t, pendingID, page.Grants[0].PendingAppealId)
	page = read(strings.Replace(query, "offset=0", "offset=50", 1))
	require.EqualValues(t, 55, page.Total)
	require.Len(t, page.Grants, 5)
	for i, g := range page.Grants {
		require.Equal(t, wantIDs[4-i], g.Id)
	}

	page = read(strings.Replace(query, "with_pending_appeal=true", "with_pending_appeal=false", 1))
	require.Empty(t, page.Grants[0].PendingAppealId)
	page = read(strings.Replace(query, "inactive_grant_policy=2", "inactive_grant_policy=1", 1))
	require.EqualValues(t, 56, page.Total, "include-all history must remain unchanged")
	require.Equal(t, superseded, page.Grants[0].Id)

	w := httptest.NewRecorder()
	mux.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/v1beta1/me/grants?"+query, nil))
	require.Equal(t, http.StatusUnauthorized, w.Code)
}
