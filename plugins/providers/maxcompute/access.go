package maxcompute

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/aliyun/aliyun-odps-go-sdk/odps/restclient"
	"github.com/goto/guardian/domain"
	"github.com/goto/guardian/pkg/alicatalogapis"
)

type accessTarget struct {
	resourceType, urn, project, schema, table, principal, overrideRole, defaultRole string
	permissions                                                                     []string
	timeout                                                                         time.Duration
}

type accessSession struct {
	query   func(context.Context, string) (string, error)
	catalog alicatalogapis.Client
}

func accessTargetFromGrant(pc *domain.ProviderConfig, g domain.Grant) (accessTarget, error) {
	var t accessTarget
	if pc == nil || g.Resource == nil {
		return t, errors.New("MaxCompute provider config and resource are required")
	}
	if g.AccountType != accountTypeRAMUser && g.AccountType != accountTypeRAMRole {
		return t, fmt.Errorf("unsupported MaxCompute account type %q", g.AccountType)
	}
	cfg := &config{pc}
	creds, err := cfg.getCredentials()
	if err != nil {
		return t, err
	}
	t.timeout, err = creds.verificationTimeout()
	if err != nil {
		return t, err
	}
	t.resourceType, t.urn, t.principal = g.Resource.Type, g.Resource.URN, g.AccountID
	var count int
	switch t.resourceType {
	case resourceTypeProject:
		count = 1
	case resourceTypeSchema:
		count = 2
	case resourceTypeTable:
		count = 3
	default:
		return t, fmt.Errorf("unsupported resource type: %s", t.resourceType)
	}
	parts := strings.Split(t.urn, ".")
	if len(parts) != count {
		return t, fmt.Errorf("invalid %s URN %q", t.resourceType, t.urn)
	}
	for _, part := range append(append([]string{}, parts...), t.principal) {
		if !safeAccessIdentifier(part) {
			return t, errors.New("empty or unsafe MaxCompute resource/principal identifier")
		}
	}
	t.project = parts[0]
	if count >= 2 {
		t.schema = parts[1]
	}
	if count == 3 {
		t.table = parts[2]
	}
	if g.Resource.Name != "" && g.Resource.Name != parts[count-1] {
		return t, fmt.Errorf("resource name does not match URN %q", t.urn)
	}
	for _, permission := range g.Permissions {
		if !safeAccessIdentifier(permission) {
			return t, errors.New("empty or unsafe MaxCompute permission")
		}
		if t.resourceType == resourceTypeTable {
			permission = strings.ToLower(permission)
			if !slices.Contains(validTableActions, permission) {
				return t, fmt.Errorf("invalid table permission %q", permission)
			}
		}
		if !slices.Contains(t.permissions, permission) {
			t.permissions = append(t.permissions, permission)
		}
	}
	if len(t.permissions) == 0 {
		return t, errors.New("MaxCompute grant permissions are required")
	}
	if slices.Contains(pc.GetParameterKeys(), parameterRAMRoleKey) {
		t.overrideRole, _, err = getParametersFromGrant[string](g, parameterRAMRoleKey)
		if err != nil {
			return t, err
		}
	}
	if t.resourceType == resourceTypeSchema {
		t.defaultRole = creds.SchemaDefaultPolicy
	}
	return t, nil
}

func safeAccessIdentifier(s string) bool {
	return s != "" && s == strings.TrimSpace(s) && !strings.ContainsAny(s, "`\x00\n\r")
}

func (p *provider) newAccessSession(pc *domain.ProviderConfig, t accessTarget) (*accessSession, error) {
	if p.accessSessionFactory != nil {
		return p.accessSessionFactory(pc, t)
	}
	s := &accessSession{}
	if t.resourceType == resourceTypeSchema {
		client, err := p.getCatalogAPIsClient(pc, t.overrideRole)
		if err != nil {
			return nil, err
		}
		s.catalog = client
	} else {
		client, err := p.getOdpsClient(pc, t.overrideRole)
		if err != nil {
			return nil, err
		}
		s.query = func(ctx context.Context, query string) (string, error) {
			return runSecurityQuery(ctx, client.RestClient(), t.project, query)
		}
	}
	return s, nil
}

func (p *provider) changeAccess(ctx context.Context, pc *domain.ProviderConfig, g domain.Grant, grant bool) error {
	if g.AccountType == domain.AccountTypePackage {
		return nil
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	target, err := accessTargetFromGrant(pc, g)
	if err != nil {
		return err
	}
	session, err := p.newAccessSession(pc, target)
	if err != nil {
		return err
	}
	operation := "revoke"
	if grant {
		operation = "grant"
	}
	// Bound mutation separately. Readback gets one fresh budget, never one per
	// permission; caller cancellation still governs both phases.
	mutationCtx, cancel := context.WithTimeout(ctx, securityCommandTimeout)
	mutationErr := session.mutate(mutationCtx, target, grant)
	cancel()
	if mutationErr != nil && !ambiguousAccessWrite(mutationErr) {
		return fmt.Errorf("MaxCompute %s on %q failed; partial changes may remain: %w", operation, target.urn, mutationErr)
	}
	expected := append([]string(nil), target.permissions...)
	if grant && target.defaultRole != "" {
		expected = append(expected, defaultRoleKey(target.defaultRole))
	}
	start := time.Now()
	attempts, err := verifyAccess(ctx, target.timeout, operation, target.urn, expected, grant, func(ctx context.Context) (map[string]bool, error) {
		return session.read(ctx, target, grant)
	})
	if p.logger != nil {
		outcome := "confirmed"
		if err != nil {
			outcome = "unconfirmed"
		}
		p.logger.Info(ctx, "MaxCompute access verification", "operation", operation, "resource_type", target.resourceType, "resource_urn", target.urn, "attempts", attempts, "duration_ms", time.Since(start).Milliseconds(), "outcome", outcome)
	}
	if err != nil {
		return errors.Join(err, mutationErr)
	}
	return nil
}

func defaultRoleKey(role string) string { return "project-role:" + role }

func (s *accessSession) mutate(ctx context.Context, t accessTarget, grant bool) error {
	switch t.resourceType {
	case resourceTypeProject:
		// Validate before making any changes. Revoke does not require a role to
		// still exist: a deleted role is already absent.
		if grant {
			for _, role := range t.permissions {
				if role == projectPermissionMember {
					continue
				}
				if _, err := s.query(ctx, fmt.Sprintf("DESCRIBE ROLE `%s`;", role)); err != nil {
					return err
				}
			}
			if slices.Contains(t.permissions, projectPermissionMember) {
				if err := s.write(ctx, fmt.Sprintf("ADD USER `%s`;", t.principal), true); err != nil {
					return err
				}
			}
		}
		for _, role := range t.permissions {
			if role == projectPermissionMember {
				continue
			}
			command := fmt.Sprintf("REVOKE `%s` FROM `%s`;", role, t.principal)
			if grant {
				command = fmt.Sprintf("GRANT `%s` TO `%s`;", role, t.principal)
			}
			if err := s.write(ctx, command, grant); err != nil {
				return err
			}
		}
		if !grant && slices.Contains(t.permissions, projectPermissionMember) {
			return s.removeMember(ctx, t)
		}
	case resourceTypeSchema:
		for _, role := range t.permissions {
			if grant {
				_, err := s.catalog.RoleBindingSchemaCreate(ctx, &alicatalogapis.RoleBindingSchemaCreateRequest{Project: t.project, Schema: t.schema, RoleName: role, Members: []string{t.principal}})
				if err != nil {
					return err
				}
			} else {
				err := s.catalog.RoleBindingSchemaDelete(ctx, &alicatalogapis.RoleBindingSchemaDeleteRequest{Project: t.project, Schema: t.schema, RoleName: role, Members: []string{t.principal}})
				if err != nil && !missingAccessObject(err) {
					return err
				}
			}
		}
		if grant && t.defaultRole != "" {
			_, err := s.catalog.RoleBindingProjectCreate(ctx, &alicatalogapis.RoleBindingProjectCreateRequest{Project: t.project, RoleName: t.defaultRole, Members: []string{t.principal}})
			return err
		}
	case resourceTypeTable:
		action, direction := "REVOKE", "FROM"
		if grant {
			action, direction = "GRANT", "TO"
		}
		return s.write(ctx, fmt.Sprintf("%s %s ON TABLE `%s`.`%s`.`%s` %s USER `%s`;", action, formatTableActions(t.permissions), t.project, t.schema, t.table, direction, t.principal), grant)
	}
	return nil
}

func (s *accessSession) write(ctx context.Context, query string, grant bool) error {
	_, err := s.query(ctx, query)
	var httpErr restclient.HttpError
	if grant && errors.As(err, &httpErr) && httpErr.ErrorMessage != nil && httpErr.StatusCode == http.StatusConflict && httpErr.ErrorMessage.ErrorCode == "ObjectAlreadyExists" {
		return nil
	}
	if !grant && missingAccessObject(err) {
		return nil
	}
	return err
}

func (s *accessSession) removeMember(ctx context.Context, t accessTarget) error {
	// Preserve the existing membership-removal contract: detach project roles
	// when MaxCompute reports DeleteConflict. Bound it instead of recursing.
	for attempt := 0; attempt < 3; attempt++ {
		err := s.write(ctx, fmt.Sprintf("REMOVE USER `%s`;", t.principal), false)
		if err == nil {
			return nil
		}
		var httpErr restclient.HttpError
		if !errors.As(err, &httpErr) || httpErr.ErrorMessage == nil || httpErr.ErrorMessage.ErrorCode != "DeleteConflict" || attempt == 2 {
			return err
		}
		roles, err := s.projectRoles(ctx, t.principal)
		if err != nil {
			return err
		}
		for _, role := range roles {
			if !safeAccessIdentifier(role) {
				return fmt.Errorf("%w: invalid project role", errInvalidAccessResponse)
			}
			if err := s.write(ctx, fmt.Sprintf("REVOKE `%s` FROM `%s`;", role, t.principal), false); err != nil {
				return err
			}
		}
		if err := waitAccessRetry(ctx, time.Duration(attempt+1)*100*time.Millisecond); err != nil {
			return err
		}
	}
	return errors.New("MaxCompute project membership removal exhausted attempts")
}

func missingAccessObject(err error) bool {
	if err == nil {
		return false
	}
	if isTableNotFoundErr(err) {
		return true
	}
	var httpErr restclient.HttpError
	if errors.As(err, &httpErr) && httpErr.ErrorMessage != nil {
		return httpErr.StatusCode == http.StatusNotFound && httpErr.ErrorMessage.ErrorCode == "NoSuchObject"
	}
	// CatalogAPI currently exposes JSON-formatted errors rather than typed
	// status codes. Require both the status and the backend absence code.
	return strings.Contains(err.Error(), `"status_code": 404`) && strings.Contains(err.Error(), "NoSuchObject")
}

func ambiguousAccessWrite(err error) bool {
	var uncertain *uncertainCommandError
	if errors.As(err, &uncertain) {
		return true
	}
	// CatalogAPI wraps transport failures. Its ETag conflict retries already
	// re-read the current policy and are separate from access propagation.
	return err != nil && (strings.Contains(err.Error(), "fail to send request") || strings.Contains(err.Error(), `"status_code": 5`))
}
