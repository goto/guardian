package maxcompute

import (
	"context"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aliyun/aliyun-odps-go-sdk/odps/account"
	"github.com/aliyun/aliyun-odps-go-sdk/odps/restclient"
	"github.com/stretchr/testify/require"
)

func queryTestClient(server *httptest.Server) restclient.RestClient {
	return restclient.NewOdpsRestClient(account.NewAliyunAccount("test-id", "test-secret"), server.URL)
}

func TestSecurityQuerySyncAndAsync(t *testing.T) {
	for _, async := range []bool{false, true} {
		t.Run(fmt.Sprint(async), func(t *testing.T) {
			var posts, gets atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method == http.MethodPost {
					posts.Add(1)
					require.Equal(t, "/projects/p/authorization", r.URL.Path)
					require.Contains(t, r.Header.Get("Content-Type"), "xml")
					var body struct {
						Query                string
						ResponseInJsonFormat bool
					}
					require.NoError(t, xml.NewDecoder(r.Body).Decode(&body))
					require.Equal(t, "LIST USERS;", body.Query)
					require.True(t, body.ResponseInJsonFormat)
					if async {
						w.WriteHeader(http.StatusAccepted)
						fmt.Fprint(w, `<Authorization><Result>job-id</Result></Authorization>`)
					} else {
						fmt.Fprint(w, `<Authorization><Result>[]</Result></Authorization>`)
					}
				} else {
					gets.Add(1)
					require.Equal(t, "/projects/p/authorization/job-id", r.URL.Path)
					fmt.Fprint(w, `<AuthorizationQuery><Status>Terminated</Status><Result>[]</Result></AuthorizationQuery>`)
				}
			}))
			defer server.Close()
			result, err := runSecurityQuery(context.Background(), queryTestClient(server), "p", "LIST USERS;")
			require.NoError(t, err)
			require.Equal(t, "[]", result)
			require.EqualValues(t, 1, posts.Load())
			if async {
				require.EqualValues(t, 1, gets.Load())
			} else {
				require.Zero(t, gets.Load())
			}
		})
	}
}

func TestSecurityQueryDeadlineAndNoWriteReplay(t *testing.T) {
	for _, phase := range []string{"submit", "poll", "running", "lost-response"} {
		t.Run(phase, func(t *testing.T) {
			var posts atomic.Int32
			release := make(chan struct{})
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method == http.MethodPost {
					posts.Add(1)
					io.Copy(io.Discard, r.Body)
					if phase == "submit" {
						select {
						case <-r.Context().Done():
						case <-release:
						}
						return
					}
					if phase == "lost-response" {
						conn, _, err := w.(http.Hijacker).Hijack()
						if err == nil {
							conn.Close()
						}
						return
					}
					w.WriteHeader(http.StatusAccepted)
					fmt.Fprint(w, `<Authorization><Result>job-id</Result></Authorization>`)
					return
				}
				if phase == "poll" {
					select {
					case <-r.Context().Done():
					case <-release:
					}
					return
				}
				fmt.Fprint(w, `<AuthorizationQuery><Status>Running</Status></AuthorizationQuery>`)
			}))
			defer server.Close()
			defer close(release)
			ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
			defer cancel()
			start := time.Now()
			_, err := runSecurityQuery(ctx, queryTestClient(server), "p", "GRANT `reader` TO `RAM$1:2`;")
			var uncertain *uncertainCommandError
			require.ErrorAs(t, err, &uncertain)
			require.EqualValues(t, 1, posts.Load())
			require.Less(t, time.Since(start), time.Second)
		})
	}
}

func TestSecurityQueryRetriesOnlyKnownRejections(t *testing.T) {
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.WriteHeader(http.StatusConflict)
		fmt.Fprint(w, `<Error><Code>Conflict</Code><Message>There is a concurrent statement conflict.</Message></Error>`)
	}))
	defer server.Close()
	_, err := runSecurityQuery(context.Background(), queryTestClient(server), "p", "GRANT `reader` TO `RAM$1:2`;")
	require.Error(t, err)
	require.EqualValues(t, 3, calls.Load())
}
