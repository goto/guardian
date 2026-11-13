package maxcompute

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"

	maxcompute "github.com/alibabacloud-go/maxcompute-20220104/client"
	"github.com/aliyun/aliyun-odps-go-sdk/odps"
	"github.com/aliyun/aliyun-odps-go-sdk/odps/restclient"
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
			loaded := p.batchLoadTablesSkippingFailures(ctx, invoker.BatchLoadTables, tables[i:end], project.Name, schema.Name)
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

func (p *provider) batchLoadTablesSkippingFailures(ctx context.Context, loadTables func([]string) ([]*odps.Table, error), tableNames []string, projectName, schemaName string) []*odps.Table {
	if len(tableNames) == 0 {
		return nil
	}
	if err := ctx.Err(); err != nil {
		p.logger.Warn(ctx, "BatchLoadTables skipped because context is done", "project", projectName, "schema", schemaName, "table_count", len(tableNames), "error", err)
		return nil
	}

	loaded, err := loadTables(tableNames)
	if err == nil {
		return loaded
	}

	if len(tableNames) == 1 {
		p.logger.Warn(ctx, "table failed to load, skipping", "project", projectName, "schema", schemaName, "table", tableNames[0], "error", err)
		return nil
	}

	p.logger.Warn(ctx, "BatchLoadTables failed, splitting batch", "project", projectName, "schema", schemaName, "table_count", len(tableNames), "error", err)
	mid := len(tableNames) / 2
	loaded = p.batchLoadTablesSkippingFailures(ctx, loadTables, tableNames[:mid], projectName, schemaName)
	return append(loaded, p.batchLoadTablesSkippingFailures(ctx, loadTables, tableNames[mid:], projectName, schemaName)...)
}

// extractComment reads the full comment JSON from a table's metadata.
func extractComment(t *odps.Table) map[string]interface{} {
	comment := t.Comment()
	if comment == "" {
		return nil
	}
	var data map[string]interface{}
	comment = strings.NewReplacer("\n", `\n`, "\r", `\r`, "\t", `\t`).Replace(comment)
	if err := json.Unmarshal([]byte(comment), &data); err != nil {
		return nil
	}
	return data
}

// formatTableActions canonicalizes the new cold-read actions for the backend while
// preserving existing actions. Normalize before deduplication so case variants
// accepted by config validation generate only one GRANT/REVOKE action.
func formatTableActions(actions []string) string {
	canonical := make([]string, len(actions))
	for i, action := range actions {
		switch strings.ToLower(action) {
		case strings.ToLower(tableActionReadLowFrequencyStorage):
			canonical[i] = tableActionReadLowFrequencyStorage
		case strings.ToLower(tableActionReadLongTermStorage):
			canonical[i] = tableActionReadLongTermStorage
		default:
			canonical[i] = action
		}
	}
	return strings.Join(slices.GenericsStandardizeSlice(canonical), ", ")
}

// isTableNotFoundErr reports whether err is a MaxCompute "table not found" error
// (ODPS-0130131). When revoking a role on a table that has already been dropped,
// the grant is effectively gone, so callers can treat this as a no-op.
func isTableNotFoundErr(err error) bool {
	if err == nil {
		return false
	}
	return strings.Contains(err.Error(), "ODPS-0130131")
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

	manager, err := cachedClientManager(p.mu, p.restClientsCache, cacheKeyFrags, func() (*aliclientmanager.Manager[*maxcompute.Client], error) {
		return aliclientmanager.NewConfig[*maxcompute.Client](manCreds, clientInitFunc)
	})
	if err != nil {
		return nil, err
	}
	return manager.GetClient()
}

func (p *provider) getOdpsClient(pc *domain.ProviderConfig, overrideRamRole string) (*odps.Odps, error) {
	cacheKeyFrags, manCreds, err := p.getClientCredentials(pc, overrideRamRole)
	if err != nil {
		return nil, err
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

	manager, err := cachedClientManager(p.mu, p.odpsClientsCache, cacheKeyFrags, func() (*aliclientmanager.Manager[*odps.Odps], error) {
		return aliclientmanager.NewConfig[*odps.Odps](manCreds, clientInitFunc)
	})
	if err != nil {
		return nil, err
	}
	return manager.GetClient()
}

func (p *provider) getCatalogAPIsClient(pc *domain.ProviderConfig, overrideRamRole string) (alicatalogapis.Client, error) {
	cacheKeyFrags, manCreds, err := p.getClientCredentials(pc, overrideRamRole)
	if err != nil {
		return nil, err
	}

	clientInitFunc := func(c aliclientmanager.Credentials) (alicatalogapis.Client, error) {
		return alicatalogapis.NewClient(c.AccessKeyId, c.AccessKeySecret, c.RegionId, c.AccountId,
			alicatalogapis.WithSecurityToken(c.SecurityToken),
		)
	}

	manager, err := cachedClientManager(p.mu, p.catalogAPIsClientsCache, cacheKeyFrags, func() (*aliclientmanager.Manager[alicatalogapis.Client], error) {
		return aliclientmanager.NewConfig[alicatalogapis.Client](manCreds, clientInitFunc)
	})
	if err != nil {
		return nil, err
	}
	return manager.GetClient()
}

// ---------------------------------------------------------------------------------------------------------------------
// Utils
// ---------------------------------------------------------------------------------------------------------------------

// odpsShouldRetry [TESTED] this was a common acquired errors by the caller when using odps client.
// To address this, we just need to simply retry the request.
func odpsShouldRetry(ctx context.Context, err error) bool {
	if ctx.Err() != nil || err == nil {
		return false
	}
	switch {
	case strings.Contains(strings.ToLower(err.Error()), strings.ToLower("Request rejected by catalog server throttling")):
		fallthrough
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

func (p *provider) listResourceAccessForUsers(ctx context.Context, overrideRAMRole string, pc *domain.ProviderConfig, resource *domain.Resource, users []string) ([]domain.AccessEntry, error) {
	switch resource.Type {
	case resourceTypeProject:
		parts := strings.SplitN(resource.URN, ".", 1)
		if len(parts) != 1 {
			return nil, fmt.Errorf("invalid project URN %q: expected project", resource.URN)
		}
		return p.listProjectAccessForUsers(ctx, overrideRAMRole, pc, parts[0], users)
	case resourceTypeSchema:
		parts := strings.SplitN(resource.URN, ".", 2)
		if len(parts) != 2 {
			return nil, fmt.Errorf("invalid schema URN %q: expected project.schema", resource.URN)
		}
		return p.listSchemaAccess(ctx, overrideRAMRole, pc, parts[0], parts[1], users...)
	case resourceTypeTable:
		parts := strings.SplitN(resource.URN, ".", 3)
		if len(parts) != 3 {
			return nil, fmt.Errorf("invalid table URN %q: expected project.schema.table", resource.URN)
		}
		return p.listTableAccess(ctx, overrideRAMRole, pc, parts[0], parts[1], parts[2], users...)
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

	// LIST USERS returns the set of RAM users added to the project via ADD USER.
	// Response format: ["RAM$accId:userName", ...]
	rawUsers, err := runSecurityQuery(ctx, odpsClient.RestClient(), project, "LIST USERS;")
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

	entries, err := p.listProjectAccessForUsers(ctx, overrideRAMRole, pc, project, listUsersResponse)
	if err != nil {
		return nil, fmt.Errorf("listing project access for %q: %w", project, err)
	}

	return entries, nil
}

func (p *provider) listProjectAccessForUsers(ctx context.Context, overrideRAMRole string, pc *domain.ProviderConfig, project string, users []string) ([]domain.AccessEntry, error) {
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("listing project access for users in %q: %w", project, err)
	}

	odpsClient, err := p.getOdpsClient(pc, overrideRAMRole)
	if err != nil {
		return nil, fmt.Errorf("listing project access for users in %q: %w", project, err)
	}

	type userGrants struct {
		userID string
		roles  []string
	}
	var mu sync.Mutex
	var errs []error
	results := make([]userGrants, 0, len(users))
	// start the worker with 3 retries to handle throttling errors
	w := pool.NewBWorkerPool(p.concurrency,
		pool.WithErrors(&errs),
		pool.WithRetry(3))
	defer w.Shutdown()

	for i := range users {
		uid := strings.TrimSpace(users[i])
		if uid == "" {
			continue
		}
		w.Do(func() error {
			rawGrants, err := runSecurityQuery(ctx, odpsClient.RestClient(), project, fmt.Sprintf("SHOW GRANTS FOR `%s`;", uid))
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
	if len(errs) > 0 {
		p.logger.Warn(ctx, fmt.Sprintf("partial failure listing grants for users in project %q: %v", project, errs))
	}

	var entries []domain.AccessEntry
	for _, ug := range results {
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

func (p *provider) listSchemaAccess(ctx context.Context, overrideRAMRole string, pc *domain.ProviderConfig, project, schema string, users ...string) ([]domain.AccessEntry, error) {
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

	// add filter by users
	userMap := make(map[string]bool)
	for _, user := range users {
		userMap[user] = true
	}

	var entries []domain.AccessEntry
	for _, b := range binding.Policy.Bindings {
		for _, member := range b.Members {
			member = strings.TrimSpace(member)
			if member == "" || (len(users) > 0 && !userMap[member]) {
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

func (p *provider) listTableAccess(ctx context.Context, overrideRAMRole string, pc *domain.ProviderConfig, project, schema, table string, users ...string) ([]domain.AccessEntry, error) {
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("listing table access for %q.%q.%q: %w", project, schema, table, err)
	}

	odpsClient, err := p.getOdpsClient(pc, overrideRAMRole)
	if err != nil {
		return nil, fmt.Errorf("listing table access for %q.%q.%q: %w", project, schema, table, err)
	}

	var query = fmt.Sprintf("SHOW GRANTS ON TABLE `%s`.`%s`.`%s`;", project, schema, table)
	rawData, err := runSecurityQuery(ctx, odpsClient.RestClient(), project, query)
	if err != nil {
		var restErr restclient.HttpError
		if errors.As(err, &restErr) && restErr.ErrorMessage != nil {
			return nil, fmt.Errorf("listing table access for %q.%q.%q: %s", project, schema, table, restErr.ErrorMessage.Message)
		}
		return nil, fmt.Errorf("listing table access for %q.%q.%q: %w", project, schema, table, err)
	}

	return parseTableAccess(rawData, users...)
}
