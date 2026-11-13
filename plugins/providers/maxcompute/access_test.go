package maxcompute

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/aliyun/aliyun-odps-go-sdk/odps/restclient"
	"github.com/goto/guardian/domain"
	"github.com/goto/guardian/pkg/alicatalogapis"
	"github.com/goto/guardian/pkg/aliclientmanager"
	"github.com/goto/guardian/pkg/log"
	"github.com/stretchr/testify/require"
)

func accessFixture(resourceType string, permissions ...string) (*domain.ProviderConfig, domain.Grant) {
	urn := "p"
	if resourceType == resourceTypeSchema {
		urn = "p.s"
	}
	if resourceType == resourceTypeTable {
		urn = "p.s.t"
	}
	return &domain.ProviderConfig{Credentials: credentials{ProjectName: "p"}}, domain.Grant{AccountType: accountTypeRAMUser, AccountID: "RAM$1:2", Resource: &domain.Resource{Type: resourceType, URN: urn}, Permissions: permissions}
}
func providerWithSession(session *accessSession) *provider {
	p := New(sourceName, nil, log.NewNoop())
	p.accessSessionFactory = func(*domain.ProviderConfig, accessTarget) (*accessSession, error) { return session, nil }
	return p
}

func TestProviderVerifiesProjectAndTableChanges(t *testing.T) {
	for _, tc := range []struct {
		name, kind           string
		permissions          []string
		grant                bool
		users, grants, table string
		mutation             string
	}{
		{"add member", resourceTypeProject, []string{"member"}, true, `["RAM$1:2"]`, `{}`, ``, "ADD USER"},
		{"remove member", resourceTypeProject, []string{"member"}, false, `[]`, `{}`, ``, "REMOVE USER"},
		{"grant roles", resourceTypeProject, []string{"reader", "writer"}, true, `["RAM$1:2"]`, `{"Roles":["reader","writer","unrelated"]}`, ``, "GRANT"},
		{"revoke roles", resourceTypeProject, []string{"reader"}, false, `["RAM$1:2"]`, `{"Roles":["unrelated"]}`, ``, "REVOKE"},
		{"grant table", resourceTypeTable, []string{"Select", "ReadLowFrequencyStorage", "ReadLongTermStorage"}, true, ``, ``, `{"ACL":{"": [{"Action":["Select","ReadLowFrequencyStorage","ReadLongTermStorage"],"Principal":["user/RAM$1:2"]}]}}`, "GRANT"},
		{"revoke table", resourceTypeTable, []string{"Select"}, false, ``, ``, `{"ACL":{"": [{"Action":["Update"],"Principal":["user/RAM$1:2"]}]}}`, "REVOKE"},
		{"grant all", resourceTypeTable, []string{"All"}, true, ``, ``, `{"ACL":{"": [{"Action":["All"],"Principal":["user/RAM$1:2"]}]}}`, "GRANT"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var commands []string
			session := &accessSession{query: func(_ context.Context, q string) (string, error) {
				commands = append(commands, q)
				switch {
				case q == "LIST USERS;":
					return tc.users, nil
				case strings.HasPrefix(q, "SHOW GRANTS FOR"):
					return tc.grants, nil
				case strings.HasPrefix(q, "SHOW GRANTS ON TABLE"):
					return tc.table, nil
				}
				return "", nil
			}}
			pc, g := accessFixture(tc.kind, tc.permissions...)
			err := providerWithSession(session).changeAccess(context.Background(), pc, g, tc.grant)
			require.NoError(t, err)
			var writes, reads int
			for _, q := range commands {
				if strings.HasPrefix(q, tc.mutation) {
					writes++
				}
				if strings.HasPrefix(q, "SHOW ") || strings.HasPrefix(q, "LIST ") {
					reads++
				}
			}
			require.Positive(t, writes)
			require.Positive(t, reads)
		})
	}
}

func TestAccessReadAllSemantics(t *testing.T) {
	pc, g := accessFixture(resourceTypeTable, "select", "ReadLowFrequencyStorage")
	target, err := accessTargetFromGrant(pc, g)
	require.NoError(t, err)
	s := &accessSession{query: func(context.Context, string) (string, error) {
		return `{"ACL":{"": [{"Action":["All"],"Principal":["user/RAM$1:2"]}]}}`, nil
	}}
	state, err := s.read(context.Background(), target, true)
	require.NoError(t, err)
	require.True(t, state["select"])
	require.False(t, state["readlowfrequencystorage"])
	target.permissions = []string{"all"}
	s.query = func(context.Context, string) (string, error) {
		return `{"ACL":{"": [{"Action":["Select"],"Principal":["user/RAM$1:2"]}]}}`, nil
	}
	state, err = s.read(context.Background(), target, false)
	require.NoError(t, err)
	require.True(t, state["all"], "remaining direct ACL prevents successful REVOKE All verification")
}

func TestProviderHandlesUnknownAndIdempotentWrites(t *testing.T) {
	for _, tc := range []struct {
		name     string
		writeErr error
		grant    bool
		table    string
		wantErr  bool
	}{
		{"ambiguous applied", &uncertainCommandError{errors.New("response lost")}, true, `{"ACL":{"": [{"Action":["Select"],"Principal":["user/RAM$1:2"]}]}}`, false},
		{"already applied", restclient.HttpError{StatusCode: 409, ErrorMessage: &restclient.ErrorMessage{ErrorCode: "ObjectAlreadyExists"}}, true, `{"ACL":{"": [{"Action":["Select"],"Principal":["user/RAM$1:2"]}]}}`, false},
		{"missing table", errors.New("ODPS-0130131:Table not found"), false, ``, false},
		{"permission rejected", errors.New("access denied"), false, ``, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			writes := 0
			s := &accessSession{query: func(_ context.Context, q string) (string, error) {
				if strings.HasPrefix(q, "SHOW ") {
					if tc.name == "missing table" {
						return "", tc.writeErr
					}
					return tc.table, nil
				}
				writes++
				return "", tc.writeErr
			}}
			pc, g := accessFixture(resourceTypeTable, "Select")
			err := providerWithSession(s).changeAccess(context.Background(), pc, g, tc.grant)
			if tc.wantErr {
				require.ErrorIs(t, err, tc.writeErr)
			} else {
				require.NoError(t, err)
			}
			require.Equal(t, 1, writes, "no blind replay or rollback")
		})
	}
}

func TestProviderVerificationFailureDoesNotUndoOrReplay(t *testing.T) {
	writes := 0
	pc, g := accessFixture(resourceTypeTable, "Select")
	p := providerWithSession(&accessSession{query: func(_ context.Context, q string) (string, error) {
		if strings.HasPrefix(q, "SHOW ") {
			return `{"ACL":{}}`, nil
		}
		writes++
		return "", nil
	}})
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	err := p.GrantAccess(ctx, pc, g)
	require.ErrorIs(t, err, ErrAccessUnconfirmed)
	require.ErrorIs(t, err, context.DeadlineExceeded)
	require.Equal(t, 1, writes)
}

type accessCatalogFake struct {
	alicatalogapis.Client
	schema, project                                        *alicatalogapis.RoleBinding
	schemaWrites, projectWrites, schemaReads, projectReads int
	schemaReadError                                        error
}

func emptyBinding() *alicatalogapis.RoleBinding {
	return &alicatalogapis.RoleBinding{Policy: &alicatalogapis.RoleBindingPolicy{}}
}
func (c *accessCatalogFake) RoleBindingSchemaCreate(_ context.Context, r *alicatalogapis.RoleBindingSchemaCreateRequest) (*alicatalogapis.RoleBinding, error) {
	c.schemaWrites++
	c.schema.Policy.Bindings = append(c.schema.Policy.Bindings, &alicatalogapis.RoleBindingPolicyBindings{Role: r.RoleName, Members: r.Members})
	return c.schema, nil
}
func (c *accessCatalogFake) RoleBindingSchemaDelete(_ context.Context, r *alicatalogapis.RoleBindingSchemaDeleteRequest) error {
	c.schemaWrites++
	var retained []*alicatalogapis.RoleBindingPolicyBindings
	for _, b := range c.schema.Policy.Bindings {
		if b.Role != r.RoleName {
			retained = append(retained, b)
		}
	}
	c.schema.Policy.Bindings = retained
	return nil
}
func (c *accessCatalogFake) RoleBindingSchemaGetAll(context.Context, *alicatalogapis.RoleBindingSchemaGetAllRequest) (*alicatalogapis.RoleBinding, error) {
	c.schemaReads++
	return c.schema, c.schemaReadError
}
func (c *accessCatalogFake) RoleBindingProjectCreate(_ context.Context, r *alicatalogapis.RoleBindingProjectCreateRequest) (*alicatalogapis.RoleBinding, error) {
	c.projectWrites++
	c.project.Policy.Bindings = append(c.project.Policy.Bindings, &alicatalogapis.RoleBindingPolicyBindings{Role: r.RoleName, Members: r.Members})
	return c.project, nil
}
func (c *accessCatalogFake) RoleBindingProjectGetAll(context.Context, *alicatalogapis.RoleBindingProjectGetAllRequest) (*alicatalogapis.RoleBinding, error) {
	c.projectReads++
	return c.project, nil
}

func TestSchemaVerificationPreservesDefaultProjectRole(t *testing.T) {
	c := &accessCatalogFake{schema: emptyBinding(), project: emptyBinding()}
	pc, g := accessFixture(resourceTypeSchema, "schema_reader")
	pc.Credentials = credentials{ProjectName: "p", SchemaDefaultPolicy: "instancecreator"}
	p := providerWithSession(&accessSession{catalog: c})
	require.NoError(t, p.GrantAccess(context.Background(), pc, g))
	require.Equal(t, 1, c.schemaReads)
	require.Equal(t, 1, c.projectReads)
	require.NoError(t, p.RevokeAccess(context.Background(), pc, g))
	require.Equal(t, 2, c.schemaReads)
	require.Equal(t, 1, c.projectReads)
	require.Equal(t, 1, c.projectWrites)
	require.Len(t, c.project.Policy.Bindings, 1)
	require.Empty(t, c.schema.Policy.Bindings)
}

func TestSchemaReadFailureCannotConfirmRevoke(t *testing.T) {
	c := &accessCatalogFake{schema: emptyBinding(), project: emptyBinding(), schemaReadError: errors.New("CatalogAPI forbidden")}
	pc, g := accessFixture(resourceTypeSchema, "schema_reader")
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	err := providerWithSession(&accessSession{catalog: c}).RevokeAccess(ctx, pc, g)
	require.ErrorIs(t, err, ErrAccessUnconfirmed)
	require.ErrorIs(t, err, c.schemaReadError)
	require.Equal(t, 1, c.schemaWrites)
}

func TestAccessTargetValidationAndOverride(t *testing.T) {
	pc, g := accessFixture(resourceTypeTable, "Select", "SELECT")
	pc.Parameters = []*domain.ProviderParameter{{Key: parameterRAMRoleKey}}
	g.Appeal = &domain.Appeal{Details: map[string]interface{}{domain.ReservedDetailsKeyProviderParameters: map[string]interface{}{parameterRAMRoleKey: "test-role"}}}
	target, err := accessTargetFromGrant(pc, g)
	require.NoError(t, err)
	require.Equal(t, []string{"select"}, target.permissions)
	require.Equal(t, "test-role", target.overrideRole)
	g.AccountType = accountTypeRAMRole
	g.AccountID = "RAM$1:role/team"
	_, err = accessTargetFromGrant(pc, g)
	require.NoError(t, err)
	for _, urn := range []string{"p.s", "p..t", "p.s.t.extra", "p.s.`t"} {
		g.Resource.URN = urn
		_, err = accessTargetFromGrant(pc, g)
		require.Error(t, err)
	}
}

func TestPartialRoleMutationDoesNotCompensate(t *testing.T) {
	pc, g := accessFixture(resourceTypeProject, "reader", "writer")
	var writes []string
	failure := errors.New("writer rejected")
	p := providerWithSession(&accessSession{query: func(_ context.Context, q string) (string, error) {
		if strings.HasPrefix(q, "DESCRIBE ") {
			return "", nil
		}
		writes = append(writes, q)
		if strings.Contains(q, "writer") {
			return "", failure
		}
		return "", nil
	}})
	err := p.GrantAccess(context.Background(), pc, g)
	require.ErrorIs(t, err, failure)
	require.Equal(t, []string{"GRANT `reader` TO `RAM$1:2`;", "GRANT `writer` TO `RAM$1:2`;"}, writes)
}

func TestConcurrentClientCache(t *testing.T) {
	var mu sync.Mutex
	cache := map[string]*aliclientmanager.Manager[int]{}
	const n = 40
	var wg sync.WaitGroup
	got := make([]*aliclientmanager.Manager[int], n)
	for i := range got {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			var err error
			got[i], err = cachedClientManager(&mu, cache, "key", func() (*aliclientmanager.Manager[int], error) { return &aliclientmanager.Manager[int]{}, nil })
			if err != nil {
				t.Error(err)
			}
		}(i)
	}
	wg.Wait()
	for _, manager := range got {
		require.Same(t, got[0], manager)
	}
	_, err := cachedClientManager(&mu, cache, "bad", func() (*aliclientmanager.Manager[int], error) { return nil, fmt.Errorf("initialize failed") })
	require.Error(t, err)
	require.NotContains(t, cache, "bad")
}

func TestMemberRemovalConflictIsBounded(t *testing.T) {
	pc, g := accessFixture(resourceTypeProject, "member")
	target, err := accessTargetFromGrant(pc, g)
	require.NoError(t, err)
	conflict := restclient.HttpError{StatusCode: 409, ErrorMessage: &restclient.ErrorMessage{ErrorCode: "DeleteConflict"}}
	removes, revokes := 0, 0
	s := &accessSession{query: func(_ context.Context, q string) (string, error) {
		switch {
		case strings.HasPrefix(q, "REMOVE "):
			removes++
			return "", conflict
		case strings.HasPrefix(q, "SHOW "):
			return `{"Roles":["reader"]}`, nil
		case strings.HasPrefix(q, "REVOKE "):
			revokes++
		}
		return "", nil
	}}
	require.Error(t, s.removeMember(context.Background(), target))
	require.Equal(t, 3, removes)
	require.Equal(t, 2, revokes)
}

func TestReadbackRejectsUnknownShapes(t *testing.T) {
	for _, raw := range []string{`{"ACL":{"unexpected":[{"Action":["Select"],"Principal":["user/RAM$1:2"]}]}}`, `{"ACL":{"": [{"Action":["Select"],"Principal":["unrecognized-principal"]}]}}`} {
		_, err := parseTableAccess(raw, "RAM$1:2")
		require.ErrorIs(t, err, errInvalidAccessResponse)
	}
	s := &accessSession{query: func(context.Context, string) (string, error) { return `{"unknown_format":[]}`, nil }}
	_, err := s.projectRoles(context.Background(), "RAM$1:2")
	require.ErrorIs(t, err, errInvalidAccessResponse)
}

func TestVerificationRequiresCompleteSchemaAndDefaultBindings(t *testing.T) {
	pc, g := accessFixture(resourceTypeSchema, "schema_reader")
	pc.Credentials = credentials{ProjectName: "p", SchemaDefaultPolicy: "instancecreator"}
	target, err := accessTargetFromGrant(pc, g)
	require.NoError(t, err)
	c := &accessCatalogFake{schema: emptyBinding(), project: emptyBinding()}
	c.schema.Policy.Bindings = []*alicatalogapis.RoleBindingPolicyBindings{{Role: "schema_reader", Members: []string{g.AccountID}}}
	s := &accessSession{catalog: c}
	state, err := s.read(context.Background(), target, true)
	require.NoError(t, err)
	require.True(t, state["schema_reader"])
	require.False(t, state[defaultRoleKey("instancecreator")])
	_, err = pollAccess(context.Background(), "grant", target.urn, []string{"schema_reader", defaultRoleKey("instancecreator")}, true, func(context.Context) (map[string]bool, error) { return state, nil }, func(context.Context, time.Duration) error { return context.DeadlineExceeded })
	var verification *AccessVerificationError
	require.ErrorAs(t, err, &verification)
	require.Equal(t, []string{defaultRoleKey("instancecreator")}, verification.Unresolved)
}

func TestConfiguredDeadlineCoversWholeVerification(t *testing.T) {
	seconds := 2
	pc, g := accessFixture(resourceTypeTable, "select", "update")
	pc.Credentials = credentials{ProjectName: "p", AccessVerificationTimeoutSeconds: &seconds}
	verified := false
	s := &accessSession{query: func(ctx context.Context, q string) (string, error) {
		if strings.HasPrefix(q, "SHOW ") {
			deadline, ok := ctx.Deadline()
			require.True(t, ok)
			require.InDelta(t, 2, time.Until(deadline).Seconds(), 0.1)
			verified = true
			return `{"ACL":{"": [{"Action":["Select","Update"],"Principal":["user/RAM$1:2"]}]}}`, nil
		}
		return "", nil
	}}
	require.NoError(t, providerWithSession(s).GrantAccess(context.Background(), pc, g))
	require.True(t, verified)
}

func TestConcurrentGrantAndRevokeRequests(t *testing.T) {
	// Independent operations on distinct targets must share no mutable command
	// or error variables. The server state itself is covered by readback tests.
	pc, g := accessFixture(resourceTypeTable, "select")
	p := providerWithSession(&accessSession{query: func(ctx context.Context, q string) (string, error) {
		if strings.HasPrefix(q, "SHOW ") {
			if ctx.Value(accessTestGrantKey{}) == true {
				return `{"ACL":{"": [{"Action":["Select"],"Principal":["user/RAM$1:2"]}]}}`, nil
			}
			return `{"ACL":{}}`, nil
		}
		return "", nil
	}})
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			grant := i%2 == 0
			copyGrant := g
			copyGrant.Resource = &domain.Resource{Type: resourceTypeTable, URN: fmt.Sprintf("p.s.t%d", i)}
			if err := p.changeAccess(context.WithValue(context.Background(), accessTestGrantKey{}, grant), pc, copyGrant, grant); err != nil {
				t.Error(err)
			}
		}(i)
	}
	wg.Wait()
}

type accessTestGrantKey struct{}
