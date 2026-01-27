package postgres

import (
	"context"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"sync"

	"github.com/lib/pq"
	"golang.org/x/sync/errgroup"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"

	"github.com/goto/guardian/domain"
	slicesUtil "github.com/goto/guardian/pkg/slices"
	"github.com/goto/guardian/utils"
)

type addOrderByClauseOptions struct {
	statusColumnName string
	statusesOrder    []string
	searchQuery      string
}

func addOrderByClause(db *gorm.DB, conditions []string, options addOrderByClauseOptions, allowedColumns []string) (*gorm.DB, error) {
	var orderByClauses []string
	var vars []interface{}

	for _, orderBy := range conditions {
		if strings.Contains(orderBy, "status") {
			orderByClauses = append(orderByClauses, fmt.Sprintf(`ARRAY_POSITION(ARRAY[?], %s)`, options.statusColumnName))
			vars = append(vars, options.statusesOrder)
		} else {
			columnOrder := strings.Split(orderBy, ":")
			columnName := columnOrder[0]
			if !utils.ContainsString(allowedColumns, columnName) {
				return nil, fmt.Errorf("cannot order by column %q", columnName)
			}
			if len(columnOrder) == 1 {
				orderByClauses = append(orderByClauses, fmt.Sprintf(`"%s"`, columnName))
			} else if len(columnOrder) == 2 {
				orderDirection := columnOrder[1]
				if utils.ContainsString([]string{"asc", "desc"}, orderDirection) {
					orderByClauses = append(orderByClauses, fmt.Sprintf(`"%s" %s`, columnName, orderDirection))
				} else if orderDirection == "exact_asc" && columnName == "name" {
					orderByClauses = append(orderByClauses, fmt.Sprintf(`(CASE WHEN lower("%s") = '%s' THEN 1 ELSE 2 END)`, columnName, strings.ToLower(options.searchQuery)))
				} else {
					return nil, fmt.Errorf("invalid order by direction: %s", orderDirection)
				}
			}
		}
	}

	return db.Clauses(clause.OrderBy{
		Expression: clause.Expr{
			SQL:                strings.Join(orderByClauses, ", "),
			Vars:               vars,
			WithoutParentheses: true,
		},
	}), nil
}

func addOrderBy(db *gorm.DB, orderBy string) *gorm.DB {
	if orderBy != "" {
		var column, order string
		expression := strings.Split(orderBy, ":")
		column = expression[0]
		if len(expression) == 2 {
			order = expression[1]
		}

		if utils.ContainsString([]string{"updated_at", "created_at"}, strings.ToLower(column)) {
			if utils.ContainsString([]string{"asc", "desc"}, strings.ToLower(order)) {
				return db.Order(fmt.Sprintf(`"%s" %s`, column, order))
			}
			return db.Order(column)
		}
	}

	return db
}

func generateLabelSummaries(ctx context.Context, dbGen func(context.Context) (*gorm.DB, error), baseTableName, labelColumnName string) ([]*domain.SummaryLabel, error) {
	db, err := dbGen(ctx)
	if err != nil {
		return nil, err
	}
	var rows []struct {
		Key    string
		Values pq.StringArray `gorm:"type:text[]"`
	}
	fullLabelColumn := fmt.Sprintf("%s.%s", baseTableName, labelColumnName)
	query := fmt.Sprintf(`
		SELECT
			key,
			array_agg(
				DISTINCT trim(both '"' from value::text)
				ORDER BY trim(both '"' from value::text)
			) AS values
		FROM %s,
		     jsonb_each(%s)
		WHERE %s IS NOT NULL
		  AND %s <> 'null'::jsonb
		  AND %s <> '{}'::jsonb
		  AND jsonb_typeof(value) = 'string'
		  AND trim(both '"' from value::text) <> '<nil>'
		GROUP BY key
	`,
		baseTableName,
		fullLabelColumn,
		fullLabelColumn,
		fullLabelColumn,
		fullLabelColumn,
	)
	if err = db.Raw(query).Scan(&rows).Error; err != nil {
		return nil, err
	}
	ret := make([]*domain.SummaryLabel, len(rows))
	for i, r := range rows {
		ret[i] = &domain.SummaryLabel{
			Key:    r.Key,
			Values: slicesUtil.GenericsStandardizeSlice(r.Values),
		}
		ret[i].Count = int32(len(ret[i].Values))
	}
	return ret, nil
}

func generateUniqueSummaries(ctx context.Context, dbGen func(context.Context) (*gorm.DB, error), baseTableName string, fields []string, entityGroupKeyMapping map[string]string) ([]*domain.SummaryUnique, error) {
	ret := make([]*domain.SummaryUnique, 0, len(fields))
	if len(fields) == 0 {
		return ret, nil
	}
	eg, egCtx := errgroup.WithContext(ctx)
	mu := &sync.Mutex{}
	for _, field := range fields {
		field := field
		eg.Go(func() error {
			sq := &domain.SummaryUnique{Field: field}
			vs := strings.Split(field, ".")
			if len(vs) < 2 {
				return fmt.Errorf("%w. input: %q", domain.ErrInvalidUniqueInput, field)
			}

			tableName := strings.TrimSpace(vs[0])
			if tableName == "" {
				return fmt.Errorf("%w. input: %q", domain.ErrEmptyUniqueTableName, field)
			}
			tableName, ok := entityGroupKeyMapping[tableName]
			if !ok {
				return fmt.Errorf("%w. input: %q", domain.ErrNotSupportedUniqueTableName, field)
			}

			columnName := strings.TrimSpace(vs[1])
			if columnName == "" {
				return fmt.Errorf("%w. input: %q", domain.ErrEmptyUniqueColumnName, field)
			}

			cm := fmt.Sprintf("%q.%q", tableName, columnName)
			if len(vs) > 2 {
				jsonPath := vs[2:]
				for _, p := range jsonPath {
					if strings.TrimSpace(p) == "" {
						return fmt.Errorf("%w. input: %q", domain.ErrInvalidUniqueInput, field)
					}
				}
				cm = buildJSONTextExpr(tableName, columnName, jsonPath)
			}
			db, err := dbGen(egCtx)
			if err != nil {
				return err
			}
			if err = db.Table(baseTableName).
				Distinct(cm).
				Pluck(cm, &sq.Values).Error; err != nil {
				return err
			}
			sq.Count = int32(len(sq.Values))
			sort.Slice(sq.Values, func(i, j int) bool {
				return fmt.Sprint(sq.Values[i]) < fmt.Sprint(sq.Values[j])
			})
			mu.Lock()
			ret = append(ret, sq)
			mu.Unlock()
			return nil
		})
	}
	if err := eg.Wait(); err != nil {
		return nil, err
	}
	return ret, nil
}

func generateGroupSummaries(ctx context.Context, dbGen func(context.Context) (*gorm.DB, error), baseTableName string, fields []string, distinctCountFields []string, entityGroupKeyMapping map[string]string) ([]*domain.SummaryGroup, error) {
	sg := make([]*domain.SummaryGroup, 0)
	if len(fields) == 0 {
		return sg, nil
	}

	db, err := dbGen(ctx)
	if err != nil {
		return nil, err
	}

	const countColumnAlias = "count"
	const distinctCountPrefix = "distinct_"
	selectCols, groupCols := make([]string, len(fields)), make([]string, len(fields))

	for i, field := range fields {
		vs := strings.Split(field, ".")
		if len(vs) < 2 {
			return nil, fmt.Errorf("%w. input: %q", domain.ErrInvalidGroupInput, field)
		}

		tableName := strings.TrimSpace(vs[0])
		if tableName == "" {
			return nil, fmt.Errorf("%w. input: %q", domain.ErrEmptyGroupTableName, field)
		}
		tableName, ok := entityGroupKeyMapping[tableName]
		if !ok {
			return nil, fmt.Errorf("%w. input: %q", domain.ErrNotSupportedGroupTableName, field)
		}

		columnName := strings.TrimSpace(vs[1])
		if columnName == "" {
			return nil, fmt.Errorf("%w. input: %q", domain.ErrEmptyGroupColumnName, field)
		}
		// TODO add column validation. e,g. grants.unknown_column is not valid column.
		// https://github.com/goto/guardian/pull/218#discussion_r2336292684
		// Add validation for group bys. e,g. group by 'created_at' is not make sense.

		cm := fmt.Sprintf("%q.%q", tableName, columnName)
		if len(vs) > 2 {
			jsonPath := vs[2:]
			for _, p := range jsonPath {
				if strings.TrimSpace(p) == "" {
					return nil, fmt.Errorf("%w. input: %q", domain.ErrInvalidGroupInput, field)
				}
			}
			cm = buildJSONTextExpr(tableName, columnName, jsonPath)
		}
		selectCols[i] = fmt.Sprintf("%s AS %q", cm, field)
		groupCols[i] = fmt.Sprintf("%q", field)
	}
	selectCols = append(selectCols, fmt.Sprintf("COUNT(1) AS %s", countColumnAlias))

	distinctCountColumns := make(map[string]string)
	for _, field := range distinctCountFields {
		if strings.Contains(field, ".") {
			return nil, fmt.Errorf("distinct count field must be simple column name (got %q)", field)
		}

		alias := distinctCountPrefix + field
		selectCols = append(selectCols, fmt.Sprintf("COUNT(DISTINCT LOWER(%q.%q)) AS %s", baseTableName, field, alias))
		distinctCountColumns[alias] = field
	}

	db = db.Table(baseTableName).Select(strings.Join(selectCols, ", "))
	db = db.Group(strings.Join(groupCols, ", "))

	// Execute query
	rows, err := db.Rows()
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	cols, err := rows.Columns()
	if err != nil {
		return nil, err
	}

	for rows.Next() {
		// Prepare scan destination
		values := make([]interface{}, len(cols))
		valuePtrs := make([]interface{}, len(cols))
		for i := range cols {
			valuePtrs[i] = &values[i]
		}

		if err = rows.Scan(valuePtrs...); err != nil {
			return nil, err
		}

		groupFields := make(map[string]any)
		distinctCounts := make(map[string]int32)
		var count int32
		for i, col := range cols {
			groupValues := values[:i]
			val := values[i]
			switch {
			case col == countColumnAlias:
				intValue, err := strconv.Atoi(fmt.Sprint(val))
				if err != nil {
					return nil, fmt.Errorf("invalid count value (%T) for group values: %v", val, groupValues)
				}
				count = int32(intValue)

			case strings.HasPrefix(col, distinctCountPrefix):
				fieldName := distinctCountColumns[col]
				intValue, err := strconv.Atoi(fmt.Sprint(val))
				if err != nil {
					return nil, fmt.Errorf("invalid distinct count value for %q (%T): %v", fieldName, val, val)
				}
				distinctCounts[fieldName] = int32(intValue)

			default:
				groupFields[col] = val
			}
		}

		summary := &domain.SummaryGroup{
			GroupFields: groupFields,
			Count:       count,
		}
		if len(distinctCounts) > 0 {
			summary.DistinctCounts = distinctCounts
		}

		sg = append(sg, summary)
	}
	return sg, nil
}

func generateSummaryResultCount(result *domain.SummaryResult) *domain.SummaryResult {
	if result == nil {
		return nil
	}
	var groupsCount int32
	for _, v := range result.SummaryGroups {
		groupsCount += v.Count
	}
	var uniquesCount int32
	for _, v := range result.SummaryUniques {
		uniquesCount += v.Count
	}
	var labelsCount int32
	labelsCount = int32(len(result.SummaryLabels))

	return &domain.SummaryResult{
		SummaryGroups: result.SummaryGroups,
		GroupsCount:   groupsCount,

		SummaryUniques: result.SummaryUniques,
		UniquesCount:   uniquesCount,

		SummaryLabels: result.SummaryLabels,
		LabelsCount:   labelsCount,
	}
}

func buildJSONTextExpr(table, column string, path []string) string {
	return fmt.Sprintf("COALESCE(NULLIF(%q.%q #>> '{%s}', ''), 'null')", table, column, strings.Join(path, ","))
}

func applyLikeAndInFilter(
	db *gorm.DB,
	column string,

	startsWith string,
	endsWith string,
	contains string,

	notStartsWith string,
	notEndsWith string,
	notContains string,

	in []string,
	notIn []string,

	filterName string,
) (*gorm.DB, error) {
	if (startsWith != "" || endsWith != "") && contains != "" {
		return nil, fmt.Errorf("invalid filter: %s_contains cannot be used together with %s_starts_with or %s_ends_with", filterName, filterName, filterName)
	}
	if (notStartsWith != "" || notEndsWith != "") && notContains != "" {
		return nil, fmt.Errorf("invalid filter: %s_not_contains cannot be used together with %s_not_starts_with or %s_not_ends_with", filterName, filterName, filterName)
	}

	// ---------- POSITIVE FILTERS (OR) ----------
	var posClauses []string
	var posArgs []interface{}

	if startsWith != "" {
		posClauses = append(posClauses, fmt.Sprintf(`%s LIKE ?`, column))
		posArgs = append(posArgs, startsWith+"%")
	}
	if endsWith != "" {
		posClauses = append(posClauses, fmt.Sprintf(`%s LIKE ?`, column))
		posArgs = append(posArgs, "%"+endsWith)
	}
	if contains != "" {
		posClauses = append(posClauses, fmt.Sprintf(`%s LIKE ?`, column))
		posArgs = append(posArgs, "%"+contains+"%")
	}
	if len(in) > 0 {
		posClauses = append(posClauses, fmt.Sprintf(`%s IN ?`, column))
		posArgs = append(posArgs, in)
	}

	if len(posClauses) > 0 {
		db = db.Where("("+strings.Join(posClauses, " OR ")+")", posArgs...)
	}

	// ---------- NEGATIVE FILTERS (AND) ----------
	var negClauses []string
	var negArgs []interface{}

	if notStartsWith != "" {
		negClauses = append(negClauses, fmt.Sprintf(`(%s IS NULL OR %s NOT LIKE ?)`, column, column))
		negArgs = append(negArgs, notStartsWith+"%")
	}
	if notEndsWith != "" {
		negClauses = append(negClauses, fmt.Sprintf(`(%s IS NULL OR %s NOT LIKE ?)`, column, column))
		negArgs = append(negArgs, "%"+notEndsWith)
	}
	if notContains != "" {
		negClauses = append(
			negClauses,
			fmt.Sprintf(`(%s IS NULL OR %s NOT LIKE ?)`, column, column),
		)
		negArgs = append(negArgs, "%"+notContains+"%")
	}
	if len(notIn) > 0 {
		negClauses = append(negClauses, fmt.Sprintf(`(%s IS NULL OR %s NOT IN ?)`, column, column))
		negArgs = append(negArgs, notIn)
	}

	if len(negClauses) > 0 {
		db = db.Where("("+strings.Join(negClauses, " AND ")+")", negArgs...)
	}

	return db, nil
}

func applyJSONBPathsLikeAndInFilter(
	db *gorm.DB,
	column string,
	paths []string,

	startsWith string,
	endsWith string,
	contains string,

	notStartsWith string,
	notEndsWith string,
	notContains string,

	in []string,
	notIn []string,

	filterName string,
) (*gorm.DB, error) {
	if len(paths) == 0 {
		return applyJSONBKeyValueFilter(db, column,
			startsWith, endsWith, contains,
			notStartsWith, notEndsWith, notContains,
			in, notIn, filterName,
		)
	}

	// ---- Validation
	if (startsWith != "" || endsWith != "") && contains != "" {
		return nil, fmt.Errorf(
			"invalid filter: %s_contains cannot be used together with %s_starts_with or %s_ends_with",
			filterName, filterName, filterName,
		)
	}
	if (notStartsWith != "" || notEndsWith != "") && notContains != "" {
		return nil, fmt.Errorf(
			"invalid filter: %s_not_contains cannot be used together with %s_not_starts_with or %s_not_ends_with",
			filterName, filterName, filterName,
		)
	}

	// ---- Normalize & deduplicate paths
	pathSet := make(map[string]struct{})
	for _, p := range paths {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		p = strings.ReplaceAll(p, ".", ",")
		pathSet[p] = struct{}{}
	}

	var normPaths []string
	for p := range pathSet {
		normPaths = append(normPaths, p)
	}
	if len(normPaths) == 0 {
		return db, nil
	}

	// ---------- POSITIVE FILTERS (OR) ----------
	var posClauses []string
	var posArgs []interface{}

	buildLike := func(op, pattern string) {
		for _, p := range normPaths {
			posClauses = append(
				posClauses,
				fmt.Sprintf(`COALESCE(NULLIF(%s #>> '{%s}', ''), 'null') %s ?`, column, p, op),
			)
			posArgs = append(posArgs, pattern)
		}
	}

	if startsWith != "" {
		buildLike("LIKE", startsWith+"%")
	}
	if endsWith != "" {
		buildLike("LIKE", "%"+endsWith)
	}
	if contains != "" {
		buildLike("LIKE", "%"+contains+"%")
	}

	if len(in) > 0 {
		for _, p := range normPaths {
			posClauses = append(
				posClauses,
				fmt.Sprintf(`COALESCE(NULLIF(%s #>> '{%s}', ''), 'null') IN ?`, column, p),
			)
			posArgs = append(posArgs, in)
		}
	}

	if len(posClauses) > 0 {
		db = db.Where("("+strings.Join(posClauses, " OR ")+")", posArgs...)
	}

	// ---------- NEGATIVE FILTERS (AND) ----------
	var negClauses []string
	var negArgs []interface{}

	buildNotLike := func(op, pattern string) {
		for _, p := range normPaths {
			negClauses = append(
				negClauses,
				fmt.Sprintf(`COALESCE(NULLIF(%s #>> '{%s}', ''), 'null') %s ?`, column, p, op),
			)
			negArgs = append(negArgs, pattern)
		}
	}

	if notStartsWith != "" {
		buildNotLike("NOT LIKE", notStartsWith+"%")
	}
	if notEndsWith != "" {
		buildNotLike("NOT LIKE", "%"+notEndsWith)
	}
	if notContains != "" {
		buildNotLike("NOT LIKE", "%"+notContains+"%")
	}

	if len(notIn) > 0 {
		for _, p := range normPaths {
			negClauses = append(
				negClauses,
				fmt.Sprintf(`COALESCE(NULLIF(%s #>> '{%s}', ''), 'null') NOT IN ?`, column, p),
			)
			negArgs = append(negArgs, notIn)
		}
	}

	if len(negClauses) > 0 {
		db = db.Where("("+strings.Join(negClauses, " AND ")+")", negArgs...)
	}

	return db, nil
}

func applyJSONBKeyValueFilter(
	db *gorm.DB,
	column string,

	startsWith string,
	endsWith string,
	contains string,

	notStartsWith string,
	notEndsWith string,
	notContains string,

	in []string,
	notIn []string,

	filterName string,
) (*gorm.DB, error) {
	// ---- Validation
	if (startsWith != "" || endsWith != "") && contains != "" {
		return nil, fmt.Errorf(
			"invalid filter: %s_contains cannot be used with %s_starts_with or %s_ends_with",
			filterName, filterName, filterName,
		)
	}
	if (notStartsWith != "" || notEndsWith != "") && notContains != "" {
		return nil, fmt.Errorf(
			"invalid filter: %s_not_contains cannot be used with %s_not_starts_with or %s_not_ends_with",
			filterName, filterName, filterName,
		)
	}

	// ---- Parse k:v  →  path , value
	parseKV := func(s string) (path string, value string, ok bool) {
		parts := strings.SplitN(s, ":", 2)
		if len(parts) != 2 {
			return "", "", false
		}
		path = strings.ReplaceAll(strings.TrimSpace(parts[0]), ".", ",")
		value = strings.TrimSpace(parts[1])
		if path == "" || value == "" {
			return "", "", false
		}
		return path, value, true
	}

	// =====================================================================
	// POSITIVE FILTERS
	// same key  → OR
	// diff key  → AND
	// =====================================================================
	posClausesByPath := map[string][]string{}
	posArgsByPath := map[string][]interface{}{}

	addPos := func(path, clause string, arg interface{}) {
		posClausesByPath[path] = append(posClausesByPath[path], clause)
		posArgsByPath[path] = append(posArgsByPath[path], arg)
	}

	buildLike := func(op, raw string, pattern func(string) string) {
		if p, v, ok := parseKV(raw); ok {
			addPos(
				p,
				fmt.Sprintf(
					`COALESCE(NULLIF(%s #>> '{%s}', ''), 'null') %s ?`,
					column, p, op,
				),
				pattern(v),
			)
		}
	}

	if startsWith != "" {
		buildLike("LIKE", startsWith, func(v string) string { return v + "%" })
	}
	if endsWith != "" {
		buildLike("LIKE", endsWith, func(v string) string { return "%" + v })
	}
	if contains != "" {
		buildLike("LIKE", contains, func(v string) string { return "%" + v + "%" })
	}

	if len(in) > 0 {
		group := map[string][]string{}
		for _, raw := range in {
			if p, v, ok := parseKV(raw); ok {
				group[p] = append(group[p], v)
			}
		}
		for p, values := range group {
			addPos(
				p,
				fmt.Sprintf(
					`COALESCE(NULLIF(%s #>> '{%s}', ''), 'null') IN ?`,
					column, p,
				),
				values,
			)
		}
	}

	// Assemble POSITIVE SQL
	if len(posClausesByPath) > 0 {
		var groups []string
		var args []interface{}

		for p, clauses := range posClausesByPath {
			groups = append(groups, "("+strings.Join(clauses, " OR ")+")")
			args = append(args, posArgsByPath[p]...)
		}

		db = db.Where(strings.Join(groups, " AND "), args...)
	}

	// =====================================================================
	// NEGATIVE FILTERS
	// same key  → AND
	// diff key  → AND
	// =====================================================================
	negClausesByPath := map[string][]string{}
	negArgsByPath := map[string][]interface{}{}

	addNeg := func(path, clause string, arg interface{}) {
		negClausesByPath[path] = append(negClausesByPath[path], clause)
		negArgsByPath[path] = append(negArgsByPath[path], arg)
	}

	buildNotLike := func(op, raw string, pattern func(string) string) {
		if p, v, ok := parseKV(raw); ok {
			addNeg(
				p,
				fmt.Sprintf(
					`COALESCE(NULLIF(%s #>> '{%s}', ''), 'null') %s ?`,
					column, p, op,
				),
				pattern(v),
			)
		}
	}

	if notStartsWith != "" {
		buildNotLike("NOT LIKE", notStartsWith, func(v string) string { return v + "%" })
	}
	if notEndsWith != "" {
		buildNotLike("NOT LIKE", notEndsWith, func(v string) string { return "%" + v })
	}
	if notContains != "" {
		buildNotLike("NOT LIKE", notContains, func(v string) string { return "%" + v + "%" })
	}

	if len(notIn) > 0 {
		group := map[string][]string{}
		for _, raw := range notIn {
			if p, v, ok := parseKV(raw); ok {
				group[p] = append(group[p], v)
			}
		}
		for p, values := range group {
			addNeg(
				p,
				fmt.Sprintf(
					`COALESCE(NULLIF(%s #>> '{%s}', ''), 'null') NOT IN ?`,
					column, p,
				),
				values,
			)
		}
	}

	// Assemble NEGATIVE SQL
	if len(negClausesByPath) > 0 {
		var groups []string
		var args []interface{}

		for p, clauses := range negClausesByPath {
			groups = append(groups, "("+strings.Join(clauses, " AND ")+")")
			args = append(args, negArgsByPath[p]...)
		}

		db = db.Where(strings.Join(groups, " AND "), args...)
	}

	return db, nil
}
