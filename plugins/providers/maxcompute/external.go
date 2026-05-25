package maxcompute

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"strings"
	"sync"

	maxcompute "github.com/alibabacloud-go/maxcompute-20220104/client"
	"github.com/aliyun/aliyun-odps-go-sdk/odps"
	"github.com/aliyun/aliyun-odps-go-sdk/odps/restclient"
	"github.com/aliyun/aliyun-odps-go-sdk/odps/security"
	"github.com/bearaujus/bptr"
	"github.com/bearaujus/bworker/pool"
	"github.com/goto/guardian/domain"
	"github.com/goto/guardian/pkg/alicatalogapis"
	"github.com/goto/guardian/pkg/aliclientmanager"
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

	credentialsIdentity, err := aliclientmanager.GetCredentialsIdentity(aliclientmanager.Credentials{
		AccessKeyId:     credentials.AccessKeyID,
		AccessKeySecret: credentials.AccessKeySecret,
		RegionId:        credentials.RegionID,
		RAMRoleARN:      credentials.RAMRole,
	})
	if err != nil {
		return nil, "", fmt.Errorf("fail to get credentials identity: %w", err)
	}
	accountId := bptr.ToStringSafe(credentialsIdentity.AccountId)

	client, err := p.getRestClient(pc)
	if err != nil {
		return nil, "", fmt.Errorf("fail to initialize rest client when retrieving project: %w", err)
	}

	res, err := client.GetProject(&credentials.ProjectName, &maxcompute.GetProjectRequest{})
	if err != nil {
		return nil, "", fmt.Errorf("fail to retrieve project '%s': %w", credentials.ProjectName, err)
	}

	project := bptr.ToStringSafe(res.Body.Data.Name)

	return &domain.Resource{
		ProviderType: pc.Type,
		ProviderURN:  pc.URN,
		Type:         resourceTypeProject,
		URN:          project,
		Name:         project,
		GlobalURN:    utils.GetGlobalURN(sourceName, accountId, resourceTypeProject, project),
	}, accountId, nil
}

func (p *provider) getSchemasFromProject(ctx context.Context, pc *domain.ProviderConfig, overrideRAMRole, accountID string, project *domain.Resource) ([]*domain.Resource, error) {
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("fail to retrieve schemas from '%s': %w", project.Name, err)
	}

	odpsClient, err := p.getOdpsClient(pc, overrideRAMRole)
	if err != nil {
		return nil, fmt.Errorf("fail to initialize odps client when retrieving schemas from '%s': %w", project.Name, err)
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
		if errors.As(err, &restErr) && restErr.ErrorMessage != nil {
			return nil, fmt.Errorf("fail to retrieve schemas from '%s': %s", project.Name, restErr.ErrorMessage.Message)
		}
		return nil, fmt.Errorf("fail to retrieve schemas from '%s': %w", project.Name, err)
	}
	if errL != nil {
		if odpsShouldRetry(ctx, errL) {
			return p.getSchemasFromProject(ctx, pc, overrideRAMRole, accountID, project)
		}
		var restErr restclient.HttpError
		if errors.As(errL, &restErr) {
			return nil, fmt.Errorf("fail to retrieve schemas from '%s': %s", project.Name, restErr.ErrorMessage.Message)
		}
		return nil, fmt.Errorf("fail to retrieve schemas from '%s': %w", project.Name, errL)
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

func (p *provider) getTablesFromSchema(ctx context.Context, pc *domain.ProviderConfig, overrideRAMRole, accountID string, project *domain.Resource, schema *domain.Resource, fetchComments bool) ([]*domain.Resource, error) {
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("fail to retrieve tables from '%s' and schema '%s': %w", project.Name, schema.Name, err)
	}

	odpsClient, err := p.getOdpsClient(pc, overrideRAMRole)
	if err != nil {
		return nil, fmt.Errorf("fail to initialize odps client when retrieving tables from '%s' and schema '%s': %w", project.Name, schema.Name, err)
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
			return p.getTablesFromSchema(ctx, pc, overrideRAMRole, accountID, project, schema, fetchComments)
		}
		var restErr restclient.HttpError
		if errors.As(err, &restErr) && restErr.ErrorMessage != nil {
			return nil, fmt.Errorf("fail to retrieve tables from '%s' and schema '%s': %s", project.Name, schema.Name, restErr.ErrorMessage.Message)
		}
		return nil, fmt.Errorf("fail to retrieve tables from '%s' and schema '%s': %w", project.Name, schema.Name, err)
	}
	tables = slices.GenericsStandardizeSlice(tables)

	// Store table comments if fetch_comments is enabled
	tableComments := make(map[string]map[string]interface{}) // tableName → parsed comment JSON
	if fetchComments {
		for i := 0; i < len(tables); i += 100 {
			end := i + 100
			if end > len(tables) {
				end = len(tables)
			}
			loaded, batchErr := invoker.BatchLoadTables(tables[i:end])
			if batchErr != nil {
				p.logger.Warn(ctx, "BatchLoadTables failed, skipping comment extraction", "project", project.Name, "schema", schema.Name, "error", batchErr)
				break
			}
			for _, t := range loaded {
				comment := extractComment(t)
				if comment != nil {
					tableComments[t.Name()] = comment
				}
			}
		}
	}

	var ret []*domain.Resource
	for _, table := range tables {
		urn := fmt.Sprintf("%s.%s.%s", project.Name, schema.Name, table)
		r := &domain.Resource{
			ProviderType: pc.Type,
			ProviderURN:  pc.URN,
			Type:         resourceTypeTable,
			URN:          urn,
			Name:         table,
			GlobalURN:    utils.GetGlobalURN(sourceName, accountID, resourceTypeTable, urn),
		}
		if comment, ok := tableComments[table]; ok {
			if r.Details == nil {
				r.Details = make(map[string]interface{})
			}
			r.Details["comment"] = comment
		}
		ret = append(ret, r)
	}
	return ret, nil
}

// extractComment reads the full comment JSON from a table's metadata.
func extractComment(t *odps.Table) map[string]interface{} {
	comment := t.Comment()
	if comment == "" {
		return nil
	}
	var data map[string]interface{}
	if err := json.Unmarshal([]byte(comment), &data); err != nil {
		return nil
	}
	return data
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
		return fmt.Errorf("fail to add member to project '%s': %w", project, err)
	}

	odpsClient, err := p.getOdpsClient(pc, overrideRAMRole)
	if err != nil {
		return fmt.Errorf("fail to initialize odps client when adding member to project '%s': %w", project, err)
	}

	var invoker = odpsClient.Project(project).SecurityManager()
	var query = fmt.Sprintf("ADD USER `%s`", ramAccountId)
	if _, err = odpsExecuteQueryOnSecurityManager(ctx, invoker, query); err != nil {
		var restErr restclient.HttpError
		if errors.As(err, &restErr) && restErr.ErrorMessage != nil {
			if restErr.StatusCode == http.StatusConflict && restErr.ErrorMessage.ErrorCode == "ObjectAlreadyExists" {
				return nil
			}
			return fmt.Errorf("fail to add member to project '%s': %s", project, restErr.ErrorMessage.Message)
		}
		return fmt.Errorf("fail to add member to project '%s': %w", project, err)
	}
	return nil
}

func (p *provider) removeMemberFromProject(ctx context.Context, pc *domain.ProviderConfig, overrideRAMRole, project, ramAccountId string) error {
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("fail to remove member from project '%s': %w", project, err)
	}

	odpsClient, err := p.getOdpsClient(pc, overrideRAMRole)
	if err != nil {
		return fmt.Errorf("fail to initialize odps client when removing member from project '%s': %w", project, err)
	}

	var invoker = odpsClient.Project(project).SecurityManager()
	var query = fmt.Sprintf("REMOVE USER `%s`", ramAccountId)
	if _, err = odpsExecuteQueryOnSecurityManager(ctx, invoker, query); err != nil {
		var restErr restclient.HttpError
		if errors.As(err, &restErr) && restErr.ErrorMessage != nil {
			// member is not exist
			if restErr.StatusCode == http.StatusNotFound && restErr.ErrorMessage.ErrorCode == "NoSuchObject" {
				return nil
			}
			// member still had attached project roles
			if restErr.StatusCode == http.StatusConflict && restErr.ErrorMessage.ErrorCode == "DeleteConflict" {
				roles, err := p.listProjectMemberRoles(ctx, pc, overrideRAMRole, project, ramAccountId)
				if err != nil {
					return fmt.Errorf("fail to remove member from project '%s': %w", project, err)
				}
				err = p.revokeProjectRolesFromMember(ctx, pc, overrideRAMRole, project, ramAccountId, roles...)
				if err != nil {
					return fmt.Errorf("fail to remove member from project '%s': %w", project, err)
				}
				return p.removeMemberFromProject(ctx, pc, overrideRAMRole, project, ramAccountId)
			}
			return fmt.Errorf("fail to remove member from project '%s': %s", project, restErr.ErrorMessage.Message)
		}
		return fmt.Errorf("fail to remove member from project '%s': %w", project, err)
	}
	return nil
}

func (p *provider) listProjectMemberRoles(ctx context.Context, pc *domain.ProviderConfig, overrideRAMRole, project, ramAccountId string) ([]string, error) {
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("fail to retrieve project member roles from '%s': %w", project, err)
	}

	odpsClient, err := p.getOdpsClient(pc, overrideRAMRole)
	if err != nil {
		return nil, fmt.Errorf("fail to initialize odps client when retrieving project member roles from '%s': %w", project, err)
	}

	var invoker = odpsClient.Project(project).SecurityManager()
	var query = fmt.Sprintf("SHOW GRANTS FOR `%s`;", ramAccountId)
	rawData, err := odpsExecuteQueryOnSecurityManager(ctx, invoker, query)
	if err != nil {
		var restErr restclient.HttpError
		if errors.As(err, &restErr) && restErr.ErrorMessage != nil {
			return nil, fmt.Errorf("fail to retrieve project member roles from '%s': %s", project, restErr.ErrorMessage.Message)
		}
		return nil, fmt.Errorf("fail to retrieve project member roles from '%s': %w", project, err)
	}
	type accessData struct {
		Roles []string `json:"Roles"`
	}
	var data = accessData{}
	if err = json.Unmarshal([]byte(rawData), &data); err != nil {
		return nil, fmt.Errorf("fail to retrieve project member roles from '%s': %w", project, err)
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

func (p *provider) grantProjectRolesToMember(ctx context.Context, pc *domain.ProviderConfig, overrideRAMRole, project, ramAccountId string, roles ...string) error {
	if len(roles) == 0 {
		return nil
	}

	if err := ctx.Err(); err != nil {
		return fmt.Errorf("fail to grant project role to '%s': %w", project, err)
	}

	odpsClient, err := p.getOdpsClient(pc, overrideRAMRole)
	if err != nil {
		return fmt.Errorf("fail to initialize odps client when granting project role to '%s': %w", project, err)
	}

	var errW error
	var w = pool.NewBWorkerPool(p.concurrency, pool.WithError(&errW))
	defer w.Shutdown()
	var roleAdded []string
	var mu = &sync.Mutex{}

	for i := range roles {
		role := roles[i]
		w.Do(func() error {
			var invoker = odpsClient.Project(project).SecurityManager()
			var query = fmt.Sprintf("GRANT `%s` TO `%s`;", role, ramAccountId)
			if _, err = odpsExecuteQueryOnSecurityManager(ctx, invoker, query); err != nil {
				var restErr restclient.HttpError
				if errors.As(err, &restErr) && restErr.ErrorMessage != nil {
					if restErr.StatusCode == http.StatusConflict && restErr.ErrorMessage.ErrorCode == "ObjectAlreadyExists" {
						return nil
					}
					return fmt.Errorf(restErr.ErrorMessage.Message)
				}
				return err
			}
			mu.Lock()
			roleAdded = append(roleAdded, role)
			mu.Unlock()
			return nil
		})
	}

	w.Wait()
	if errW != nil {
		// rollback
		_ = p.revokeProjectRolesFromMember(ctx, pc, overrideRAMRole, project, ramAccountId, roleAdded...)
		return fmt.Errorf("fail to grant project role to '%s': %w", project, errW)
	}
	return nil
}

func (p *provider) revokeProjectRolesFromMember(ctx context.Context, pc *domain.ProviderConfig, overrideRAMRole, project, ramAccountId string, roles ...string) error {
	if len(roles) == 0 {
		return nil
	}

	if err := ctx.Err(); err != nil {
		return fmt.Errorf("fail to revoke project role from '%s': %w", project, err)
	}

	odpsClient, err := p.getOdpsClient(pc, overrideRAMRole)
	if err != nil {
		return fmt.Errorf("fail to initialize odps client when revoking project role from '%s': %w", project, err)
	}

	var errW error
	var w = pool.NewBWorkerPool(p.concurrency, pool.WithError(&errW))
	defer w.Shutdown()
	var roleRevoked []string
	var mu = &sync.Mutex{}

	for i := range roles {
		role := roles[i]
		w.Do(func() error {
			var invoker = odpsClient.Project(project).SecurityManager()
			var query = fmt.Sprintf("REVOKE `%s` FROM `%s`;", role, ramAccountId)
			if _, err = odpsExecuteQueryOnSecurityManager(ctx, invoker, query); err != nil {
				var restErr restclient.HttpError
				if errors.As(err, &restErr) && restErr.ErrorMessage != nil {
					if restErr.StatusCode == http.StatusNotFound && restErr.ErrorMessage.ErrorCode == "NoSuchObject" && !regexp.MustCompile(`^the role '[^']+' does not exist$`).MatchString(restErr.ErrorMessage.Message) {
						return nil
					}
					return errors.New(restErr.ErrorMessage.Message)
				}
				return err
			}
			mu.Lock()
			roleRevoked = append(roleRevoked, role)
			mu.Unlock()
			return nil
		})
	}

	w.Wait()
	if errW != nil {
		// rollback
		_ = p.grantProjectRolesToMember(ctx, pc, overrideRAMRole, project, ramAccountId, roleRevoked...)
		return fmt.Errorf("fail to revoke project role from '%s': %w", project, errW)
	}
	return nil
}

func (p *provider) validateProjectRole(ctx context.Context, pc *domain.ProviderConfig, overrideRAMRole, project string, roles ...string) error {
	if len(roles) == 0 {
		return nil
	}

	if err := ctx.Err(); err != nil {
		return fmt.Errorf("fail to validate project role from '%s': %w", project, err)
	}

	odpsClient, err := p.getOdpsClient(pc, overrideRAMRole)
	if err != nil {
		return fmt.Errorf("fail to initialize odps client when validating project role from '%s': %w", project, err)
	}

	var errW error
	var w = pool.NewBWorkerPool(p.concurrency, pool.WithError(&errW))
	defer w.Shutdown()

	for i := range roles {
		role := roles[i]
		w.Do(func() error {
			var invoker = odpsClient.Project(project).SecurityManager()
			var query = fmt.Sprintf("DESCRIBE ROLE `%s`;", role)
			if _, err = odpsExecuteQueryOnSecurityManager(ctx, invoker, query); err != nil {
				var restErr restclient.HttpError
				if errors.As(err, &restErr) && restErr.ErrorMessage != nil {
					return errors.New(restErr.ErrorMessage.Message)
				}
				return err
			}
			return nil
		})
	}

	w.Wait()
	if errW != nil {
		return fmt.Errorf("fail to validate project role from '%s': %w", project, errW)
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
	if len(roles) == 0 {
		return nil
	}

	if err := ctx.Err(); err != nil {
		return fmt.Errorf("fail to grant table role to '%s.%s.%s': %w", project, schema, table, err)
	}

	odpsClient, err := p.getOdpsClient(pc, overrideRAMRole)
	if err != nil {
		return fmt.Errorf("fail to initialize odps client when granting table role to '%s.%s.%s': %w", project, schema, table, err)
	}

	var invoker = odpsClient.Project(project).SecurityManager()
	roleQuery := strings.Join(slices.GenericsStandardizeSlice(roles), ", ")
	var query = fmt.Sprintf("GRANT %s ON TABLE `%s`.`%s`.`%s` TO USER `%s`;", roleQuery, project, schema, table, ramAccountId)
	if _, err = odpsExecuteQueryOnSecurityManager(ctx, invoker, query); err != nil {
		var restErr restclient.HttpError
		if errors.As(err, &restErr) && restErr.ErrorMessage != nil {
			if restErr.StatusCode == http.StatusConflict && restErr.ErrorMessage.ErrorCode == "ObjectAlreadyExists" {
				return nil
			}
			return fmt.Errorf("fail to grant table role to '%s.%s.%s': %s", project, schema, table, restErr.ErrorMessage.Message)
		}
		return fmt.Errorf("fail to grant table role to '%s.%s.%s': %w", project, schema, table, err)
	}
	return nil
}

func (p *provider) revokeTableRolesFromMember(ctx context.Context, pc *domain.ProviderConfig, overrideRAMRole, project, schema, table, ramAccountId string, roles ...string) error {
	if len(roles) == 0 {
		return nil
	}

	if err := ctx.Err(); err != nil {
		return fmt.Errorf("fail to revoke table role from '%s.%s.%s': %w", project, schema, table, err)
	}

	odpsClient, err := p.getOdpsClient(pc, overrideRAMRole)
	if err != nil {
		return fmt.Errorf("fail to initialize odps client when revoking table role from '%s.%s.%s': %w", project, schema, table, err)
	}

	var invoker = odpsClient.Project(project).SecurityManager()
	roleQuery := strings.Join(slices.GenericsStandardizeSlice(roles), ", ")
	var query = fmt.Sprintf("REVOKE %s ON TABLE `%s`.`%s`.`%s` FROM USER `%s`", roleQuery, project, schema, table, ramAccountId)
	if _, err = odpsExecuteQueryOnSecurityManager(ctx, invoker, query); err != nil {
		var restErr restclient.HttpError
		if errors.As(err, &restErr) && restErr.ErrorMessage != nil {
			return fmt.Errorf("fail to revoke table role from '%s.%s.%s': %s", project, schema, table, restErr.ErrorMessage.Message)
		}
		return fmt.Errorf("fail to revoke table role from '%s.%s.%s': %w", project, schema, table, err)
	}
	return nil
}

// ---------------------------------------------------------------------------------------------------------------------
// External Client
// ---------------------------------------------------------------------------------------------------------------------

func (p *provider) getClientCredentials(pc *domain.ProviderConfig, overrideRamRole string) (string, aliclientmanager.Credentials, error) {
	creds, err := p.getCreds(pc)
	if err != nil {
		return "", aliclientmanager.Credentials{}, err
	}
	ramRole := overrideRamRole
	if creds.RAMRole != "" {
		ramRole = creds.RAMRole
	}
	cacheKeyFrags := fmt.Sprintf("%s:%s:%s", creds.AccessKeyID, creds.RegionID, ramRole)
	manCreds := aliclientmanager.Credentials{
		AccessKeyId:     creds.AccessKeyID,
		AccessKeySecret: creds.AccessKeySecret,
		RegionId:        creds.RegionID,
		RAMRoleARN:      ramRole,
	}
	return cacheKeyFrags, manCreds, nil
}

func (p *provider) getRestClient(pc *domain.ProviderConfig) (*maxcompute.Client, error) {
	cacheKeyFrags, manCreds, err := p.getClientCredentials(pc, "")
	if err != nil {
		return nil, err
	}

	if c, exists := p.restClientsCache[cacheKeyFrags]; exists {
		restClient, err := c.GetClient()
		if err != nil {
			return nil, err
		}
		return restClient, nil
	}

	clientInitFunc := func(c aliclientmanager.Credentials) (*maxcompute.Client, error) {
		aliyunCreds, err := c.ToOpenAPIConfig()
		if err != nil {
			return nil, err
		}
		var endpoint = fmt.Sprintf("maxcompute.%s.aliyuncs.com", c.RegionId)
		aliyunCreds.Endpoint = bptr.FromStringNilAble(endpoint)
		restClient, err := maxcompute.NewClient(aliyunCreds)
		if err != nil {
			return nil, err
		}
		return restClient, nil
	}

	manager, err := aliclientmanager.NewConfig[*maxcompute.Client](manCreds, clientInitFunc)
	if err != nil {
		return nil, err
	}

	p.mu.Lock()
	p.restClientsCache[cacheKeyFrags] = manager
	p.mu.Unlock()

	return p.getRestClient(pc)
}

func (p *provider) getOdpsClient(pc *domain.ProviderConfig, overrideRamRole string) (*odps.Odps, error) {
	cacheKeyFrags, manCreds, err := p.getClientCredentials(pc, overrideRamRole)
	if err != nil {
		return nil, err
	}

	if c, exists := p.odpsClientsCache[cacheKeyFrags]; exists {
		odpsClient, err := c.GetClient()
		if err != nil {
			return nil, err
		}
		return odpsClient, nil
	}

	clientInitFunc := func(c aliclientmanager.Credentials) (*odps.Odps, error) {
		odpsAccount, err := c.ToODPSAccount()
		if err != nil {
			return nil, err
		}
		var endpoint = fmt.Sprintf("http://service.%s.maxcompute.aliyun.com/api", c.RegionId)
		var odpsClient = odps.NewOdps(odpsAccount, endpoint)
		return odpsClient, nil
	}

	manager, err := aliclientmanager.NewConfig[*odps.Odps](manCreds, clientInitFunc)
	if err != nil {
		return nil, err
	}

	p.mu.Lock()
	p.odpsClientsCache[cacheKeyFrags] = manager
	p.mu.Unlock()

	return p.getOdpsClient(pc, overrideRamRole)
}

func (p *provider) getCatalogAPIsClient(pc *domain.ProviderConfig, overrideRamRole string) (alicatalogapis.Client, error) {
	cacheKeyFrags, manCreds, err := p.getClientCredentials(pc, overrideRamRole)
	if err != nil {
		return nil, err
	}

	if c, exists := p.catalogAPIsClientsCache[cacheKeyFrags]; exists {
		catalogAPIsClient, err := c.GetClient()
		if err != nil {
			return nil, err
		}
		return catalogAPIsClient, nil
	}

	clientInitFunc := func(c aliclientmanager.Credentials) (alicatalogapis.Client, error) {
		return alicatalogapis.NewClient(c.AccessKeyId, c.AccessKeySecret, c.RegionId, c.AccountId,
			alicatalogapis.WithSecurityToken(c.SecurityToken),
		)
	}

	manager, err := aliclientmanager.NewConfig[alicatalogapis.Client](manCreds, clientInitFunc)
	if err != nil {
		return nil, err
	}

	p.mu.Lock()
	p.catalogAPIsClientsCache[cacheKeyFrags] = manager
	p.mu.Unlock()

	return p.getCatalogAPIsClient(pc, overrideRamRole)
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

// ---------------------------------------------------------------------------------------------------------------------
// List Access
// ---------------------------------------------------------------------------------------------------------------------

func inferAccountType(member string) string {
	if strings.Contains(member, ":role/") {
		return accountTypeRAMRole
	}
	return accountTypeRAMUser
}

func (p *provider) listResourceAccess(ctx context.Context, overrideRAMRole string, pc *domain.ProviderConfig, resource *domain.Resource) ([]domain.AccessEntry, error) {
	switch resource.Type {
	case resourceTypeProject:
		return p.listProjectAccess(ctx, overrideRAMRole, pc, resource.URN)
	case resourceTypeSchema:
		parts := strings.SplitN(resource.URN, ".", 2)
		if len(parts) != 2 {
			return nil, fmt.Errorf("invalid schema URN %q: expected project.schema", resource.URN)
		}
		return p.listSchemaAccess(ctx, overrideRAMRole, pc, parts[0], parts[1])
	case resourceTypeTable:
		parts := strings.SplitN(resource.URN, ".", 3)
		if len(parts) != 3 {
			return nil, fmt.Errorf("invalid table URN %q: expected project.schema.table", resource.URN)
		}
		return p.listTableAccess(ctx, overrideRAMRole, pc, parts[0], parts[1], parts[2])
	default:
		return nil, fmt.Errorf("unsupported resource type: %s", resource.Type)
	}
}

func (p *provider) listProjectAccess(ctx context.Context, overrideRAMRole string, pc *domain.ProviderConfig, project string) ([]domain.AccessEntry, error) {
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("listing project access for %q: %w", project, err)
	}

	odpsClient, err := p.getOdpsClient(pc, overrideRAMRole)
	if err != nil {
		return nil, fmt.Errorf("listing project access for %q: %w", project, err)
	}

	invoker := odpsClient.Project(project).SecurityManager()

	// LIST USERS returns the set of RAM users added to the project via ADD USER.
	// Response format: {"Users": ["RAM$accId:userName", ...]}
	rawUsers, err := odpsExecuteQueryOnSecurityManager(ctx, invoker, "LIST USERS;")
	if err != nil {
		var restErr restclient.HttpError
		if errors.As(err, &restErr) && restErr.ErrorMessage != nil {
			return nil, fmt.Errorf("listing project users for %q: %s", project, restErr.ErrorMessage.Message)
		}
		return nil, fmt.Errorf("listing project users for %q: %w", project, err)
	}

	var listUsersResponse []string
	if err = json.Unmarshal([]byte(rawUsers), &listUsersResponse); err != nil {
		return nil, fmt.Errorf("listing project access for %q: failed to parse users response: %w", project, err)
	}

	type userGrants struct {
		userID string
		roles  []string
	}

	var mu sync.Mutex
	var errW error
	results := make([]userGrants, 0, len(listUsersResponse))
	w := pool.NewBWorkerPool(p.concurrency, pool.WithError(&errW))
	defer w.Shutdown()

	for i := range listUsersResponse {
		uid := strings.TrimSpace(listUsersResponse[i])
		if uid == "" {
			continue
		}
		w.Do(func() error {
			rawGrants, err := odpsExecuteQueryOnSecurityManager(ctx, invoker, fmt.Sprintf("SHOW GRANTS FOR `%s`;", uid))
			if err != nil {
				var restErr restclient.HttpError
				if errors.As(err, &restErr) && restErr.ErrorMessage != nil {
					return fmt.Errorf("listing grants for %q in project %q: %s", uid, project, restErr.ErrorMessage.Message)
				}
				return fmt.Errorf("listing grants for %q in project %q: %w", uid, project, err)
			}
			type grantsResponse struct {
				Roles []string `json:"Roles"`
			}
			var grantsData grantsResponse
			if err = json.Unmarshal([]byte(rawGrants), &grantsData); err != nil {
				return fmt.Errorf("parsing grants for %q in project %q: %w", uid, project, err)
			}
			mu.Lock()
			results = append(results, userGrants{userID: uid, roles: grantsData.Roles})
			mu.Unlock()
			return nil
		})
	}
	w.Wait()
	if errW != nil {
		return nil, errW
	}

	var entries []domain.AccessEntry
	for _, ug := range results {
		// Being listed as a project user means the ADD USER grant was applied.
		entries = append(entries, domain.AccessEntry{
			AccountID:   ug.userID,
			AccountType: inferAccountType(ug.userID),
			Permission:  projectPermissionMember,
		})
		for _, role := range ug.roles {
			entries = append(entries, domain.AccessEntry{
				AccountID:   ug.userID,
				AccountType: inferAccountType(ug.userID),
				Permission:  role,
			})
		}
	}
	return entries, nil
}

func (p *provider) listSchemaAccess(ctx context.Context, overrideRAMRole string, pc *domain.ProviderConfig, project, schema string) ([]domain.AccessEntry, error) {
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("listing schema access for %q.%q: %w", project, schema, err)
	}

	client, err := p.getCatalogAPIsClient(pc, overrideRAMRole)
	if err != nil {
		return nil, fmt.Errorf("listing schema access for %q.%q: %w", project, schema, err)
	}

	binding, err := client.RoleBindingSchemaGetAll(ctx, &alicatalogapis.RoleBindingSchemaGetAllRequest{
		Project: project,
		Schema:  schema,
	})
	if err != nil {
		return nil, fmt.Errorf("listing schema access for %q.%q: %w", project, schema, err)
	}

	var entries []domain.AccessEntry
	for _, b := range binding.Policy.Bindings {
		for _, member := range b.Members {
			member = strings.TrimSpace(member)
			if member == "" {
				continue
			}
			entries = append(entries, domain.AccessEntry{
				AccountID:   member,
				AccountType: inferAccountType(member),
				Permission:  b.Role,
			})
		}
	}
	return entries, nil
}

func (p *provider) listTableAccess(ctx context.Context, overrideRAMRole string, pc *domain.ProviderConfig, project, schema, table string) ([]domain.AccessEntry, error) {
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("listing table access for %q.%q.%q: %w", project, schema, table, err)
	}

	odpsClient, err := p.getOdpsClient(pc, overrideRAMRole)
	if err != nil {
		return nil, fmt.Errorf("listing table access for %q.%q.%q: %w", project, schema, table, err)
	}

	var invoker = odpsClient.Project(project).SecurityManager()
	var query = fmt.Sprintf("SHOW GRANTS ON TABLE `%s`.`%s`.`%s`;", project, schema, table)
	rawData, err := odpsExecuteQueryOnSecurityManager(ctx, invoker, query)
	if err != nil {
		var restErr restclient.HttpError
		if errors.As(err, &restErr) && restErr.ErrorMessage != nil {
			return nil, fmt.Errorf("listing table access for %q.%q.%q: %s", project, schema, table, restErr.ErrorMessage.Message)
		}
		return nil, fmt.Errorf("listing table access for %q.%q.%q: %w", project, schema, table, err)
	}

	type aclEntry struct {
		Action    []string `json:"Action"`
		Effect    string   `json:"Effect"`
		Principal []string `json:"Principal"`
	}
	type tableGrantsResponse struct {
		ACL map[string][]aclEntry `json:"ACL"`
	}
	var data tableGrantsResponse
	if err = json.Unmarshal([]byte(rawData), &data); err != nil {
		return nil, fmt.Errorf("listing table access for %q.%q.%q: failed to parse response: %w", project, schema, table, err)
	}

	var entries []domain.AccessEntry
	for _, entry := range data.ACL[""] {
		for _, principal := range entry.Principal {
			// Principal format: "user/RAM$ACCOUNTID:ROLEORUSER(acs:odps:*:...)"
			after, ok := strings.CutPrefix(principal, "user/")
			if !ok {
				continue
			}
			idx := strings.Index(after, "(")
			if idx == -1 {
				continue
			}
			accountID := after[:idx]
			accountType := inferAccountType(accountID)
			for _, action := range entry.Action {
				entries = append(entries, domain.AccessEntry{
					AccountID:   accountID,
					AccountType: accountType,
					Permission:  strings.ToUpper(action),
				})
			}
		}
	}
	return entries, nil
}
