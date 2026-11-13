package postgres_test

import (
	"context"
	"database/sql"
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/goto/guardian/pkg/log"
	"github.com/goto/guardian/pkg/postgrestest"
)

// Use the real migration runner and representative data, including generic
// prepared plans. Timing is diagnostic only; plan eligibility is the assertion.
func TestSlowQueryIndexesWithPreparedPlans(t *testing.T) {
	if testing.Short() {
		t.Skip("requires owned disposable PostgreSQL")
	}
	store, pool, resource, err := postgrestest.NewTestStore(log.NewNoop())
	if err != nil {
		t.Fatal(err)
	}
	db, err := store.DB().DB()
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		_ = db.Close()
		if err := postgrestest.PurgeTestDocker(pool, resource); err != nil {
			t.Error(err)
		}
	}()
	ctx := context.Background()
	conn, err := db.Conn(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	exec := func(s string) {
		t.Helper()
		if _, err := conn.ExecContext(ctx, s); err != nil {
			t.Fatal(err)
		}
	}
	migrations := []string{"000037_add_resource_listing_index", "000038_add_grant_account_lookup_index"}
	apply := func(direction string) {
		t.Helper()
		for _, name := range migrations {
			data, err := os.ReadFile("migrations/" + name + "." + direction + ".sql")
			if err != nil {
				t.Fatal(err)
			}
			exec(string(data))
		}
	}
	// NewTestStore has applied both concurrent migrations successfully. Exercise
	// rollback before comparing the old and new access paths on the same data.
	apply("down")
	exec(`INSERT INTO providers(type,urn) VALUES ('fixture_target','fixture'),('fixture_bulk','fixture')`)
	exec(`INSERT INTO resources(id,provider_type,provider_urn,type,urn,name,global_urn,is_deleted,created_at,updated_at,deleted_at)
 SELECT md5('r'||i::text)::uuid, CASE WHEN i%10=0 THEN 'fixture_target' ELSE 'fixture_bulk' END,
 'fixture', CASE WHEN i%3=0 THEN 'table' ELSE 'project' END, i::text,'synthetic resource',
 'fixture://'||md5(i::text), i%17=0, NOW(),NOW(),CASE WHEN i%19=0 THEN NOW() ELSE NULL END
 FROM generate_series(1,100000) i`)
	exec(`INSERT INTO grants(id,account_id,account_type,status,resource_id,role,permissions,created_at,updated_at,deleted_at)
 SELECT md5('g'||i::text)::uuid,'User'||lpad((i%5000)::text,5,'0')||'@example.test','user',
 CASE WHEN i%3=0 THEN 'inactive' ELSE 'active' END,md5('r'||i::text)::uuid,'reader',ARRAY['read'],
 NOW(),NOW(),CASE WHEN i%23=0 THEN NOW() ELSE NULL END FROM generate_series(1,100000) i`)
	exec("VACUUM ANALYZE resources")
	exec("VACUUM ANALYZE grants")
	exec("SET plan_cache_mode=force_generic_plan")
	exec(`PREPARE resource_list(text,text,boolean,integer,integer) AS SELECT * FROM resources
 WHERE provider_type=$1 AND type=$2 AND is_deleted=$3 AND deleted_at IS NULL ORDER BY global_urn LIMIT $4 OFFSET $5`)
	exec(`PREPARE resource_count(text,text,boolean) AS SELECT count(*) FROM resources
 WHERE provider_type=$1 AND type=$2 AND is_deleted=$3 AND deleted_at IS NULL`)
	exec(`PREPARE grant_list(text,text) AS SELECT * FROM grants
 WHERE LOWER(account_id)=$1 AND status=$2 AND deleted_at IS NULL ORDER BY updated_at DESC LIMIT 20`)
	exec(`PREPARE grant_count(text,text) AS SELECT count(*) FROM grants
 WHERE LOWER(account_id)=$1 AND status=$2 AND deleted_at IS NULL`)
	cases := []struct{ name, query, index string }{
		{"resource_list", `EXECUTE resource_list('fixture_target','table',false,200,0)`, "idx_resources_filter_global_urn"},
		{"resource_count", `EXECUTE resource_count('fixture_target','table',false)`, "idx_resources_filter_global_urn"},
		{"grant_list", `EXECUTE grant_list('user00017@example.test','active')`, "idx_grants_lower_account_status_resource"},
		{"grant_count", `EXECUTE grant_count('user00017@example.test','active')`, "idx_grants_lower_account_status_resource"},
	}
	for _, tc := range cases {
		t.Logf("before %s: %s", tc.name, explainIndexPlan(t, ctx, conn, tc.query))
	}
	apply("up")
	for _, tc := range cases {
		plan := explainIndexPlan(t, ctx, conn, tc.query)
		t.Logf("after %s: %s", tc.name, plan)
		if !strings.Contains(plan, tc.index) {
			t.Fatalf("generic prepared plan does not use %s", tc.index)
		}
	}
	var valid int
	if err := conn.QueryRowContext(ctx, `SELECT count(*) FROM pg_index i JOIN pg_class c ON c.oid=i.indexrelid
 WHERE c.relname IN ('idx_resources_filter_global_urn','idx_grants_lower_account_status_resource') AND i.indisvalid AND i.indisready`).Scan(&valid); err != nil || valid != 2 {
		t.Fatalf("indexes not ready: %d %v", valid, err)
	}
	apply("down")
	if err := conn.QueryRowContext(ctx, `SELECT count(*) FROM pg_class WHERE relname IN ('idx_resources_filter_global_urn','idx_grants_lower_account_status_resource')`).Scan(&valid); err != nil || valid != 0 {
		t.Fatalf("rollback retained indexes: %d %v", valid, err)
	}
}

func explainIndexPlan(t *testing.T, ctx context.Context, conn *sql.Conn, query string) string {
	t.Helper()
	var data []byte
	if err := conn.QueryRowContext(ctx, "EXPLAIN (ANALYZE, BUFFERS, FORMAT JSON) "+query).Scan(&data); err != nil {
		t.Fatal(err)
	}
	var plan interface{}
	if err := json.Unmarshal(data, &plan); err != nil {
		t.Fatal(err)
	}
	compact, _ := json.Marshal(plan)
	return string(compact)
}
