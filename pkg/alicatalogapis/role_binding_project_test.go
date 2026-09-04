package alicatalogapis

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRoleBindingProjectCreateRetriesConcurrentModification(t *testing.T) {
	var getCalls atomic.Int32
	var setCalls atomic.Int32

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/catalog/v1alpha/projects/project-1:getPolicy":
			getCalls.Add(1)
			w.Header().Set("Content-Type", "application/json")
			_, err := fmt.Fprint(w, `{"etag":"etag-1","bindings":[]}`)
			require.NoError(t, err)
		case "/api/catalog/v1alpha/projects/project-1:setPolicy":
			call := setCalls.Add(1)
			w.Header().Set("Content-Type", "application/json")
			if call == 1 {
				w.WriteHeader(http.StatusBadRequest)
				_, err := fmt.Fprint(w, `{"code":400,"message":"role bindings of this object have been modified","reason":"InvalidArgument"}`)
				require.NoError(t, err)
				return
			}
			_, err := fmt.Fprint(w, `{"etag":"etag-2","bindings":[]}`)
			require.NoError(t, err)
		default:
			t.Fatalf("unexpected request: %s %s", r.Method, r.URL.Path)
		}
	}))
	defer server.Close()

	client := &client{
		accessKeyID:     "key",
		accessKeySecret: "secret",
		accountID:       "account-1",
		host:            server.URL,
		httpClient:      server.Client(),
	}

	_, err := client.RoleBindingProjectCreate(context.Background(), &RoleBindingProjectCreateRequest{
		Project:  "project-1",
		RoleName: "project_schema_member",
		Members:  []string{"RAM$1:1"},
	})
	require.NoError(t, err)
	assert.Equal(t, int32(2), getCalls.Load())
	assert.Equal(t, int32(2), setCalls.Load())
}
