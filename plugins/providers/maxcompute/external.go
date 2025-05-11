package maxcompute

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"strings"

	maxcompute "github.com/alibabacloud-go/maxcompute-20220104/client"
	"github.com/aliyun/aliyun-odps-go-sdk/odps"
	"github.com/aliyun/aliyun-odps-go-sdk/odps/restclient"
	"github.com/aliyun/aliyun-odps-go-sdk/odps/security"
	"github.com/bearaujus/bptr"
	"github.com/goto/guardian/domain"
	"github.com/goto/guardian/pkg/aliauth"
	"github.com/goto/guardian/pkg/alicatalogapis"
	"github.com/goto/guardian/pkg/slices"
	"github.com/goto/guardian/utils"
)

// ---------------------------------------------------------------------------------------------------------------------
// Project Metadata
// ---------------------------------------------------------------------------------------------------------------------

func (p *provider) getProject(ctx context.Context, pc *domain.ProviderConfig) (*domain.Resource, string, error) {
	if err := ctx.Err(); err != nil {
		return nil, "", fmt.Errorf("fail to retrieve project: %w", err)
	}

	credentials, err := p.getCreds(pc)
	if err != nil {
		return nil, "", fmt.Errorf("fail to get credentials when retrieving project: %w", err)
	}

	client, err := p.getRestClient(pc)
	if err != nil {
		return nil, "", fmt.Errorf("fail to initialize rest client when retrieving project: %w", err)
	}

	res, err := client.GetProject(&credentials.ProjectName, &maxcompute.GetProjectRequest{})
	if err != nil {
		return nil, "", fmt.Errorf("fail to retrieve project '%s': %w", credentials.ProjectName, err)
	}

	project := bptr.ToStringSafe(res.Body.Data.Name)
	owner := bptr.ToStringSafe(res.Body.Data.Owner)

	accountID := strings.TrimPrefix(owner, "ALIYUN$")
	if credentials.RAMRole != "" {
		ac, err := parseRoleAccountId(credentials.RAMRole)
		if err == nil {
			accountID = ac.AccountId
		}
	}

	return &domain.Resource{
		ProviderType: pc.Type,
		ProviderURN:  pc.URN,
		Type:         resourceTypeProject,
		URN:          project,
		Name:         project,
		GlobalURN:    utils.GetGlobalURN(sourceName, accountID, resourceTypeProject, project),
	}, accountID, nil
}

func (p *provider) getSchemasFromProject(ctx context.Context, pc *domain.ProviderConfig, overrideRAMRole, accountID string, project *domain.Resource) ([]*domain.Resource, error) {
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("fail to retrieve schemas from project '%s': %w", project.Name, err)
	}

	odpsClient, err := p.getOdpsClient(pc, overrideRAMRole)
	if err != nil {
		return nil, fmt.Errorf("fail to initialize odps client when retrieving schemas from project '%s': %w", project.Name, err)
	}

	var errL error
	var schemas []string
	var invoker = odpsClient.Project(project.Name).Schemas()
	err = invoker.List(func(schema *odps.Schema, errF error) {
		if errF != nil {
			errL = errF
			return
		}
		schemas = append(schemas, schema.Name())
	})
	if err != nil {
		if odpsShouldRetry(ctx, err) {
			return p.getSchemasFromProject(ctx, pc, overrideRAMRole, accountID, project)
		}
		var restErr restclient.HttpError
		if errors.As(err, &restErr) {
			return nil, fmt.Errorf("fail to retrieve schemas from project '%s': %s", project.Name, restErr.ErrorMessage.Message)
		}
		return nil, fmt.Errorf("fail to retrieve schemas from project '%s': %w", project.Name, err)
	}
	if errL != nil {
		if odpsShouldRetry(ctx, errL) {
			return p.getSchemasFromProject(ctx, pc, overrideRAMRole, accountID, project)
		}
		var restErr restclient.HttpError
		if errors.As(errL, &restErr) {
			return nil, fmt.Errorf("fail to retrieve schemas from project '%s': %s", project.Name, restErr.ErrorMessage.Message)
		}
		return nil, fmt.Errorf("fail to retrieve schemas from project '%s': %w", project.Name, errL)
	}
	schemas = slices.GenericsStandardizeSlice(schemas)

	var ret []*domain.Resource
	for _, schema := range schemas {
		urn := fmt.Sprintf("%s.%s", project.Name, schema)
		ret = append(ret, &domain.Resource{
			ProviderType: pc.Type,
			ProviderURN:  pc.URN,
			Type:         resourceTypeSchema,
			URN:          urn,
			Name:         schema,
			GlobalURN:    utils.GetGlobalURN(sourceName, accountID, resourceTypeSchema, urn),
		})
	}
	return ret, nil
}

func (p *provider) getTablesFromSchema(ctx context.Context, pc *domain.ProviderConfig, overrideRAMRole, accountID string, project *domain.Resource, schema *domain.Resource) ([]*domain.Resource, error) {
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("fail to retrieve tables from project '%s' and schema '%s': %w", project.Name, schema.Name, err)
	}

	odpsClient, err := p.getOdpsClient(pc, overrideRAMRole)
	if err != nil {
		return nil, fmt.Errorf("fail to initialize odps client when retrieving tables from project '%s' and schema '%s': %w", project.Name, schema.Name, err)
	}

	var tables []string
	var invoker = odpsClient.Project(project.Name).Schemas().Get(schema.Name).Tables()
	invoker.List(func(table *odps.Table, errF error) {
		if errF != nil {
			err = errF
			return
		}
		tables = append(tables, table.Name())
	})
	if err != nil {
		if odpsShouldRetry(ctx, err) {
			return p.getTablesFromSchema(ctx, pc, overrideRAMRole, accountID, project, schema)
		}
		var restErr restclient.HttpError
		if errors.As(err, &restErr) {
			return nil, fmt.Errorf("fail to retrieve tables from project '%s' and schema '%s': %s", project.Name, schema.Name, restErr.ErrorMessage.Message)
		}
		return nil, fmt.Errorf("fail to retrieve tables from project '%s' and schema '%s': %w", project.Name, schema.Name, err)
	}
	tables = slices.GenericsStandardizeSlice(tables)

	var ret []*domain.Resource
	for _, table := range tables {
		urn := fmt.Sprintf("%s.%s.%s", project.Name, schema.Name, table)
		ret = append(ret, &domain.Resource{
			ProviderType: pc.Type,
			ProviderURN:  pc.URN,
			Type:         resourceTypeTable,
			URN:          urn,
			Name:         table,
			GlobalURN:    utils.GetGlobalURN(sourceName, accountID, resourceTypeTable, urn),
		})
	}
	return ret, nil
}

// ---------------------------------------------------------------------------------------------------------------------
// Project Member
/* ---------------------------------------------------------------------------------------------------------------------
	A project member can be deleted only when no project-level roles are attached to them.
	This constraint ensures that role-based access control remains consistent and prevents accidental
	loss of permissions.

	Before removing a member, we need to ensure that:
	  - All project-level roles (e.g., `instancecreator`, `member`, `dataviewer`) have been revoked.

	Attempting to delete a member with active role bindings will result in a failure.
--------------------------------------------------------------------------------------------------------------------- */

func (p *provider) addMemberToProject(ctx context.Context, pc *domain.ProviderConfig, overrideRAMRole, project, ramAccountId string) error {
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("fail to add member to project from project '%s': %w", project, err)
	}

	odpsClient, err := p.getOdpsClient(pc, overrideRAMRole)
	if err != nil {
		return fmt.Errorf("fail to initialize odps client when adding member to project from project '%s': %w", project, err)
	}

	ramAccountId, err = parseAccountId(ramAccountId)
	if err != nil {
		return fmt.Errorf("fail to parse ram account id when adding member to project from project '%s': %w", project, err)
	}

	var invoker = odpsClient.Project(project).SecurityManager()
	var query = fmt.Sprintf("ADD USER `%s`", ramAccountId)
	if _, err = odpsExecuteQueryOnSecurityManager(ctx, invoker, query); err != nil {
		var restErr restclient.HttpError
		if errors.As(err, &restErr) {
			if restErr.StatusCode == http.StatusConflict && restErr.ErrorMessage.ErrorCode == "ObjectAlreadyExists" {
				return nil
			}
			return fmt.Errorf("fail to add member to project from project '%s': %s", project, restErr.ErrorMessage.Message)
		}
		return fmt.Errorf("fail to add member to project from project '%s': %w", project, err)
	}
	return nil
}

func (p *provider) removeMemberFromProject(ctx context.Context, pc *domain.ProviderConfig, overrideRAMRole, project, ramAccountId string) error {
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("fail to add member to project from project '%s': %w", project, err)
	}

	odpsClient, err := p.getOdpsClient(pc, overrideRAMRole)
	if err != nil {
		return fmt.Errorf("fail to initialize odps client when adding member to project from project '%s': %w", project, err)
	}

	ramAccountId, err = parseAccountId(ramAccountId)
	if err != nil {
		return fmt.Errorf("fail to parse ram account id when adding member to project from project '%s': %w", project, err)
	}

	var invoker = odpsClient.Project(project).SecurityManager()
	var query = fmt.Sprintf("REMOVE USER `%s`", ramAccountId)
	if _, err = odpsExecuteQueryOnSecurityManager(ctx, invoker, query); err != nil {
		var restErr restclient.HttpError
		if errors.As(err, &restErr) {
			// member is not exist
			if restErr.StatusCode == http.StatusNotFound && restErr.ErrorMessage.ErrorCode == "NoSuchObject" {
				return nil
			}
			// member still had attached project roles
			if restErr.StatusCode == http.StatusConflict && restErr.ErrorMessage.ErrorCode == "DeleteConflict" {
				roles, err := p.listProjectMemberRoles(ctx, pc, overrideRAMRole, project, ramAccountId)
				if err != nil {
					return fmt.Errorf("fail to remove project member from project '%s': %w", project, err)
				}
				for _, role := range roles {
					err = p.revokeProjectRoleFromMember(ctx, pc, overrideRAMRole, project, ramAccountId, role)
					if err != nil {
						return fmt.Errorf("fail to remove project member from project '%s': %w", project, err)
					}
				}
				return p.removeMemberFromProject(ctx, pc, overrideRAMRole, project, ramAccountId)
			}
			return fmt.Errorf("fail to remove project member from project '%s': %s", project, restErr.ErrorMessage.Message)
		}
		return fmt.Errorf("fail to remove project member from project '%s': %w", project, err)
	}
	return nil
}

func (p *provider) listProjectMemberRoles(ctx context.Context, pc *domain.ProviderConfig, overrideRAMRole, project, ramAccountId string) ([]string, error) {
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("fail to retrieve project member roles from project '%s': %w", project, err)
	}

	odpsClient, err := p.getOdpsClient(pc, overrideRAMRole)
	if err != nil {
		return nil, fmt.Errorf("fail to initialize odps client when retrieving project member roles from project '%s': %w", project, err)
	}

	ramAccountId, err = parseAccountId(ramAccountId)
	if err != nil {
		return nil, fmt.Errorf("fail to parse ram account id when retrieving project member roles from project '%s': %w", project, err)
	}

	var invoker = odpsClient.Project(project).SecurityManager()
	var query = fmt.Sprintf("SHOW GRANTS FOR `%s`;", ramAccountId)
	rawData, err := odpsExecuteQueryOnSecurityManager(ctx, invoker, query)
	if err != nil {
		var restErr restclient.HttpError
		if errors.As(err, &restErr) {
			return nil, fmt.Errorf("fail to retrieve project member roles from project '%s': %s", project, restErr.ErrorMessage.Message)
		}
		return nil, fmt.Errorf("fail to retrieve project member roles from project '%s': %w", project, err)
	}
	type accessData struct {
		Roles []string `json:"Roles"`
	}
	var data = accessData{}
	if err = json.Unmarshal([]byte(rawData), &data); err != nil {
		return nil, fmt.Errorf("fail to retrieve project member roles from project '%s': %w", project, err)
	}
	return slices.GenericsStandardizeSlice(data.Roles), nil
}

// ---------------------------------------------------------------------------------------------------------------------
// Project Level Access
/* ---------------------------------------------------------------------------------------------------------------------
	Project-level roles define what actions a user can perform across the entire MaxCompute project.

	Grant a user the `instancecreator` role:
		GRANT `instancecreator` TO USER `RAM$5123xxx:2123xxx`;
		Result: Success

	Attempt to grant the same role twice (this will fail if the role already exists):
		GRANT `instancecreator`, `dataviewer` TO USER `RAM$5123xxx:2123xxx`;
		Result: Fail – the role `instancecreator` is already granted

	> Note: Role grants are exclusive — attempting to re-grant an existing role
			to a user may result in an error.
--------------------------------------------------------------------------------------------------------------------- */

func (p *provider) grantProjectRoleToMember(ctx context.Context, pc *domain.ProviderConfig, overrideRAMRole, project, ramAccountId, role string) error {
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("fail to grant member project role from project '%s': %w", project, err)
	}

	odpsClient, err := p.getOdpsClient(pc, overrideRAMRole)
	if err != nil {
		return fmt.Errorf("fail to initialize odps client when granting member project role from project '%s': %w", project, err)
	}

	ramAccountId, err = parseAccountId(ramAccountId)
	if err != nil {
		return fmt.Errorf("fail to parse ram account id when granting member project role from project '%s': %w", project, err)
	}

	var invoker = odpsClient.Project(project).SecurityManager()
	var query = fmt.Sprintf("GRANT `%s` TO `%s`;", role, ramAccountId)
	if _, err = odpsExecuteQueryOnSecurityManager(ctx, invoker, query); err != nil {
		var restErr restclient.HttpError
		if errors.As(err, &restErr) {
			if restErr.StatusCode == http.StatusConflict && restErr.ErrorMessage.ErrorCode == "ObjectAlreadyExists" {
				return nil
			}
			return fmt.Errorf("fail to grant member project role from project '%s': %s", project, restErr.ErrorMessage.Message)
		}
		return fmt.Errorf("fail to grant member project role from project '%s': %w", project, err)
	}
	return nil
}

func (p *provider) revokeProjectRoleFromMember(ctx context.Context, pc *domain.ProviderConfig, overrideRAMRole, project, ramAccountId, role string) error {
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("fail to revoke member project role from project '%s': %w", project, err)
	}

	odpsClient, err := p.getOdpsClient(pc, overrideRAMRole)
	if err != nil {
		return fmt.Errorf("fail to initialize odps client when revoking member project role from project '%s': %w", project, err)
	}

	ramAccountId, err = parseAccountId(ramAccountId)
	if err != nil {
		return fmt.Errorf("fail to parse ram account id when revoking member project role from project '%s': %w", project, err)
	}

	var invoker = odpsClient.Project(project).SecurityManager()
	var query = fmt.Sprintf("REVOKE `%s` FROM `%s`;", role, ramAccountId)
	if _, err = odpsExecuteQueryOnSecurityManager(ctx, invoker, query); err != nil {
		var restErr restclient.HttpError
		if errors.As(err, &restErr) {
			if restErr.StatusCode == http.StatusNotFound && restErr.ErrorMessage.ErrorCode == "NoSuchObject" && !regexp.MustCompile(`^the role '[^']+' does not exist$`).MatchString(restErr.ErrorMessage.Message) {
				return nil
			}
			return fmt.Errorf("fail to revoke member project role from project '%s': %s", project, restErr.ErrorMessage.Message)
		}
		return fmt.Errorf("fail to revoke member project role from project '%s': %w", project, err)
	}
	return nil
}

func (p *provider) validateProjectRole(ctx context.Context, pc *domain.ProviderConfig, overrideRAMRole, project, role string) error {
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("fail to validate project role from project '%s': %w", project, err)
	}

	odpsClient, err := p.getOdpsClient(pc, overrideRAMRole)
	if err != nil {
		return fmt.Errorf("fail to initialize odps client when validating project role from project '%s': %w", project, err)
	}

	var invoker = odpsClient.Project(project).SecurityManager()
	var query = fmt.Sprintf("DESCRIBE ROLE `%s`;", role)
	if _, err = odpsExecuteQueryOnSecurityManager(ctx, invoker, query); err != nil {
		var restErr restclient.HttpError
		if errors.As(err, &restErr) {
			return fmt.Errorf("fail to validate project role from project '%s': %s", project, restErr.ErrorMessage.Message)
		}
		return fmt.Errorf("fail to validate project role from project '%s': %w", project, err)
	}
	return nil
}

// ---------------------------------------------------------------------------------------------------------------------
// Table Level Access
/* ---------------------------------------------------------------------------------------------------------------------
	Table-level privileges provide granular control over specific resources (schemas, tables).

	Grant a user `ALTER` privilege on a specific table:
		GRANT ALTER ON TABLE `haryo_poc_playground`.`a_schema`.`a_table`
		TO USER `RAM$5123xxx:2123xxx`;
		Result: Success

	Grant multiple privileges (e.g., `ALTER`, `DROP`) on the same table:
		GRANT ALTER, DROP ON TABLE `haryo_poc_playground`.`a_schema`.`a_table`
		TO USER `RAM$5123xxx:2123xxx`;
		Result: Success

	> Note: Table-level privileges can be granted incrementally or all at once.
			Re-granting the same privilege is allowed.
--------------------------------------------------------------------------------------------------------------------- */

func (p *provider) grantTableRolesToMember(ctx context.Context, pc *domain.ProviderConfig, overrideRAMRole, project, schema, table, ramAccountId string, roles ...string) error {
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("fail to grant member table role from '%s.%s.%s': %w", project, schema, table, err)
	}

	odpsClient, err := p.getOdpsClient(pc, overrideRAMRole)
	if err != nil {
		return fmt.Errorf("fail to initialize odps client when granting member table role from '%s.%s.%s': %w", project, schema, table, err)
	}

	ramAccountId, err = parseAccountId(ramAccountId)
	if err != nil {
		return fmt.Errorf("fail to parse ram account id when granting member table role from '%s.%s.%s': %w", project, schema, table, err)
	}

	roles = slices.GenericsStandardizeSlice(roles)
	if len(roles) == 0 {
		return fmt.Errorf("fail to grant member table role from '%s.%s.%s': empty role", project, schema, table)
	}

	var invoker = odpsClient.Project(project).SecurityManager()
	roleQuery := strings.Join(roles, ", ")
	var query = fmt.Sprintf("GRANT %s ON TABLE `%s`.`%s`.`%s` TO USER `%s`;", roleQuery, project, schema, table, ramAccountId)
	if _, err = odpsExecuteQueryOnSecurityManager(ctx, invoker, query); err != nil {
		var restErr restclient.HttpError
		if errors.As(err, &restErr) {
			if restErr.StatusCode == http.StatusConflict && restErr.ErrorMessage.ErrorCode == "ObjectAlreadyExists" {
				return nil
			}
			return fmt.Errorf("fail to grant member table role from '%s.%s.%s': %s", project, schema, table, restErr.ErrorMessage.Message)
		}
		return fmt.Errorf("fail to grant member table role from '%s.%s.%s': %w", project, schema, table, err)
	}
	return nil
}

func (p *provider) revokeTableRolesFromMember(ctx context.Context, pc *domain.ProviderConfig, overrideRAMRole, project, schema, table, ramAccountId string, roles ...string) error {
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("fail to revoke member table role from '%s.%s.%s': %w", project, schema, table, err)
	}

	odpsClient, err := p.getOdpsClient(pc, overrideRAMRole)
	if err != nil {
		return fmt.Errorf("fail to initialize odps client when revoking member table role from '%s.%s.%s': %w", project, schema, table, err)
	}

	ramAccountId, err = parseAccountId(ramAccountId)
	if err != nil {
		return fmt.Errorf("fail to parse ram account id when revoking member table role from '%s.%s.%s': %w", project, schema, table, err)
	}

	roles = slices.GenericsStandardizeSlice(roles)
	if len(roles) == 0 {
		return fmt.Errorf("fail to revoke member table role from '%s.%s.%s': empty role", project, schema, table)
	}

	var invoker = odpsClient.Project(project).SecurityManager()
	roleQuery := strings.Join(roles, ", ")
	var query = fmt.Sprintf("REVOKE %s ON TABLE `%s`.`%s`.`%s` FROM USER `%s`", roleQuery, project, schema, table, ramAccountId)
	if _, err = odpsExecuteQueryOnSecurityManager(ctx, invoker, query); err != nil {
		var restErr restclient.HttpError
		if errors.As(err, &restErr) {
			return fmt.Errorf("fail to revoke member table role from '%s.%s.%s': %s", project, schema, table, restErr.ErrorMessage.Message)
		}
		return fmt.Errorf("fail to revoke member table role from '%s.%s.%s': %w", project, schema, table, err)
	}
	return nil
}

// ---------------------------------------------------------------------------------------------------------------------
// External Client
// ---------------------------------------------------------------------------------------------------------------------

func (p *provider) getRestClient(pc *domain.ProviderConfig) (*maxcompute.Client, error) {
	creds, err := p.getCreds(pc)
	if err != nil {
		return nil, err
	}

	ramRole := p.getRamRole(creds, "")
	var aliAuthOptions []aliauth.AliAuthOption
	if ramRole != "" {
		aliAuthOptions = append(aliAuthOptions, aliauth.WithRAMRoleARN(ramRole))
	}

	authConfig, err := aliauth.NewConfig(creds.AccessKeyID, creds.AccessKeySecret, creds.RegionID, aliAuthOptions...)
	if err != nil {
		return nil, err
	}

	authCreds, err := authConfig.GetOpenAPIConfig()
	if err != nil {
		return nil, err
	}

	endpoint := fmt.Sprintf("maxcompute.%s.aliyuncs.com", creds.RegionID)
	authCreds.Endpoint = &endpoint
	restClient, err := maxcompute.NewClient(authCreds)
	if err != nil {
		return nil, err
	}

	return restClient, nil
}

func (p *provider) getOdpsClient(pc *domain.ProviderConfig, overrideRamRole string) (*odps.Odps, error) {
	creds, err := p.getCreds(pc)
	if err != nil {
		return nil, err
	}

	ramRole := p.getRamRole(creds, overrideRamRole)
	var aliAuthOptions []aliauth.AliAuthOption
	if ramRole != "" {
		aliAuthOptions = append(aliAuthOptions, aliauth.WithRAMRoleARN(ramRole))
	}

	authConfig, err := aliauth.NewConfig(creds.AccessKeyID, creds.AccessKeySecret, creds.RegionID, aliAuthOptions...)
	if err != nil {
		return nil, err
	}

	account, err := authConfig.GetAccount()
	if err != nil {
		return nil, err
	}

	endpoint := fmt.Sprintf("http://service.%s.maxcompute.aliyun.com/api", creds.RegionID)
	client := odps.NewOdps(account, endpoint)

	return client, nil
}

func (p *provider) getCatalogAPIsClient(pc *domain.ProviderConfig, overrideRamRole string) (alicatalogapis.Client, error) {
	creds, err := p.getCreds(pc)
	if err != nil {
		return nil, err
	}

	ramRole := p.getRamRole(creds, overrideRamRole)
	var aliAuthOptions []aliauth.AliAuthOption
	if ramRole != "" {
		aliAuthOptions = append(aliAuthOptions, aliauth.WithRAMRoleARN(ramRole))
	}

	authConfig, err := aliauth.NewConfig(creds.AccessKeyID, creds.AccessKeySecret, creds.RegionID, aliAuthOptions...)
	if err != nil {
		return nil, err
	}

	openAPIConfig, err := authConfig.GetOpenAPIConfig()
	if err != nil {
		return nil, err
	}
	securityToken := bptr.ToStringSafe(openAPIConfig.SecurityToken)

	var clientOptions []alicatalogapis.ClientOption
	if securityToken != "" {
		clientOptions = append(clientOptions, alicatalogapis.WithSecurityToken(securityToken))
	}

	client, err := alicatalogapis.NewClient(
		bptr.ToStringSafe(openAPIConfig.AccessKeyId),
		bptr.ToStringSafe(openAPIConfig.AccessKeySecret),
		bptr.ToStringSafe(openAPIConfig.RegionId),
		authConfig.GetAccountId(),
		clientOptions...,
	)
	if err != nil {
		return nil, err
	}

	return client, nil
}

// ---------------------------------------------------------------------------------------------------------------------
// Utils
// ---------------------------------------------------------------------------------------------------------------------

func odpsExecuteQueryOnSecurityManager(ctx context.Context, sm security.Manager, query string) (string, error) {
	if ctx.Err() != nil {
		return "", ctx.Err()
	}
	job, err := sm.Run(query, true, "")
	if err != nil {
		if odpsShouldRetry(ctx, err) {
			return odpsExecuteQueryOnSecurityManager(ctx, sm, query)
		}
		return "", err
	}
	ret, err := job.WaitForSuccess()
	if err != nil {
		if odpsShouldRetry(ctx, err) {
			return odpsExecuteQueryOnSecurityManager(ctx, sm, query)
		}
		return "", err
	}
	return ret, nil
}

// odpsShouldRetry [TESTED] this was a common acquired errors by the caller when using odps client.
// To address this, we just need to simply retry the request.
func odpsShouldRetry(ctx context.Context, err error) bool {
	if ctx.Err() != nil || err == nil {
		return false
	}
	switch {
	case strings.Contains(strings.ToLower(err.Error()), strings.ToLower("There is a concurrent statement conflict.")):
		fallthrough
	case strings.Contains(strings.ToLower(err.Error()), strings.ToLower("(Client.Timeout exceeded while awaiting headers)")):
		fallthrough
	case strings.Contains(strings.ToLower(err.Error()), strings.ToLower("read: connection reset by peer")):
		return true
	default:
		return false
	}
}
