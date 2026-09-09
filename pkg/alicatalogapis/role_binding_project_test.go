package alicatalogapis

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRoleBindingProjectCreateRetriesConcurrentModificationAndForwardsETag(t *testing.T) {
	var getCalls atomic.Int32
	var setCalls atomic.Int32
	var seenSetETags []string

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/catalog/v1alpha/projects/project-1:getPolicy":
			call := getCalls.Add(1)
			w.Header().Set("Content-Type", "application/json")
			_, err := fmt.Fprintf(w, `{"etag":"etag-%d","bindings":[{"role":"roles/admin","members":["RAM$1:role/a"]}]}`, call)
			require.NoError(t, err)
		case "/api/catalog/v1alpha/projects/project-1:setPolicy":
			call := setCalls.Add(1)
			body, err := io.ReadAll(r.Body)
			require.NoError(t, err)
			var req RoleBinding
			require.NoError(t, json.Unmarshal(body, &req))
			require.NotNil(t, req.Policy)
			seenSetETags = append(seenSetETags, req.Policy.ETag)
			assert.Equal(t, fmt.Sprintf("etag-%d", call), req.Policy.ETag)
			assert.True(t, hasBuiltinAdmin(req.Policy), "builtin roles/admin must be preserved")

			w.Header().Set("Content-Type", "application/json")
			if call == 1 {
				w.WriteHeader(http.StatusBadRequest)
				_, err := fmt.Fprint(w, `{"code":400,"message":"role bindings of this object have been modified","reason":"InvalidArgument"}`)
				require.NoError(t, err)
				return
			}
			_, err = fmt.Fprintf(w, `{"etag":"etag-final","bindings":[{"role":"roles/admin","members":["RAM$1:role/a"]},{"role":"project_schema_member","members":["RAM$1:1"]}]}`)
			require.NoError(t, err)
		default:
			t.Fatalf("unexpected request: %s %s", r.Method, r.URL.Path)
		}
	}))
	defer server.Close()

	client := testCatalogClient(server)
	_, err := client.RoleBindingProjectCreate(context.Background(), &RoleBindingProjectCreateRequest{
		Project:  "project-1",
		RoleName: "project_schema_member",
		Members:  []string{"RAM$1:1"},
	})
	require.NoError(t, err)
	assert.Equal(t, int32(2), getCalls.Load())
	assert.Equal(t, int32(2), setCalls.Load())
	assert.Equal(t, []string{"etag-1", "etag-2"}, seenSetETags)
}

func TestRoleBindingSchemaCreateRetriesConcurrentModificationAndForwardsETag(t *testing.T) {
	var getCalls atomic.Int32
	var setCalls atomic.Int32
	var seenSetETags []string

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/catalog/v1alpha/projects/project-1/schemas/schema-1:getPolicy":
			call := getCalls.Add(1)
			w.Header().Set("Content-Type", "application/json")
			_, err := fmt.Fprintf(w, `{"etag":"schema-etag-%d","bindings":[]}`, call)
			require.NoError(t, err)
		case "/api/catalog/v1alpha/projects/project-1/schemas/schema-1:setPolicy":
			call := setCalls.Add(1)
			body, err := io.ReadAll(r.Body)
			require.NoError(t, err)
			var req RoleBinding
			require.NoError(t, json.Unmarshal(body, &req))
			require.NotNil(t, req.Policy)
			seenSetETags = append(seenSetETags, req.Policy.ETag)
			assert.Equal(t, fmt.Sprintf("schema-etag-%d", call), req.Policy.ETag)

			w.Header().Set("Content-Type", "application/json")
			if call == 1 {
				w.WriteHeader(http.StatusBadRequest)
				_, err := fmt.Fprint(w, `{"code":400,"message":"role bindings of this object have been modified","reason":"InvalidArgument"}`)
				require.NoError(t, err)
				return
			}
			_, err = fmt.Fprint(w, `{"etag":"schema-etag-final","bindings":[{"role":"schema_dataviewer","members":["RAM$1:1"]}]}`)
			require.NoError(t, err)
		default:
			t.Fatalf("unexpected request: %s %s", r.Method, r.URL.Path)
		}
	}))
	defer server.Close()

	client := testCatalogClient(server)
	_, err := client.RoleBindingSchemaCreate(context.Background(), &RoleBindingSchemaCreateRequest{
		Project:  "project-1",
		Schema:   "schema-1",
		RoleName: "schema_dataviewer",
		Members:  []string{"RAM$1:1"},
	})
	require.NoError(t, err)
	assert.Equal(t, int32(2), getCalls.Load())
	assert.Equal(t, int32(2), setCalls.Load())
	assert.Equal(t, []string{"schema-etag-1", "schema-etag-2"}, seenSetETags)
}

func TestRoleBindingSchemaDeleteRetriesConcurrentModificationAndForwardsETag(t *testing.T) {
	var getCalls atomic.Int32
	var setCalls atomic.Int32
	var seenSetETags []string

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/catalog/v1alpha/projects/project-1/schemas/schema-1:getPolicy":
			call := getCalls.Add(1)
			w.Header().Set("Content-Type", "application/json")
			_, err := fmt.Fprintf(w, `{"etag":"del-etag-%d","bindings":[{"role":"schema_dataviewer","members":["RAM$1:1","RAM$1:2"]}]}`, call)
			require.NoError(t, err)
		case "/api/catalog/v1alpha/projects/project-1/schemas/schema-1:setPolicy":
			call := setCalls.Add(1)
			body, err := io.ReadAll(r.Body)
			require.NoError(t, err)
			var req RoleBinding
			require.NoError(t, json.Unmarshal(body, &req))
			require.NotNil(t, req.Policy)
			seenSetETags = append(seenSetETags, req.Policy.ETag)
			assert.Equal(t, fmt.Sprintf("del-etag-%d", call), req.Policy.ETag)

			w.Header().Set("Content-Type", "application/json")
			if call == 1 {
				w.WriteHeader(http.StatusBadRequest)
				_, err := fmt.Fprint(w, `{"code":400,"message":"role bindings of this object have been modified","reason":"InvalidArgument"}`)
				require.NoError(t, err)
				return
			}
			_, err = fmt.Fprint(w, `{"etag":"del-etag-final","bindings":[{"role":"schema_dataviewer","members":["RAM$1:2"]}]}`)
			require.NoError(t, err)
		default:
			t.Fatalf("unexpected request: %s %s", r.Method, r.URL.Path)
		}
	}))
	defer server.Close()

	client := testCatalogClient(server)
	err := client.RoleBindingSchemaDelete(context.Background(), &RoleBindingSchemaDeleteRequest{
		Project:  "project-1",
		Schema:   "schema-1",
		RoleName: "schema_dataviewer",
		Members:  []string{"RAM$1:1"},
	})
	require.NoError(t, err)
	assert.Equal(t, int32(2), getCalls.Load())
	assert.Equal(t, int32(2), setCalls.Load())
	assert.Equal(t, []string{"del-etag-1", "del-etag-2"}, seenSetETags)
}

func testCatalogClient(server *httptest.Server) *client {
	return &client{
		accessKeyID:     "key",
		accessKeySecret: "secret",
		accountID:       "account-1",
		host:            server.URL,
		httpClient:      server.Client(),
	}
}

func hasBuiltinAdmin(policy *RoleBindingPolicy) bool {
	for _, b := range policy.Bindings {
		if b != nil && b.Role == "roles/admin" {
			return true
		}
	}
	return false
}
