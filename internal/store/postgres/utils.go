package postgres

import (
	"context"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"sync"

	"golang.org/x/sync/errgroup"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"

	"github.com/goto/guardian/domain"
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

func generateUniqueSummaries(ctx context.Context, dbGen func() (*gorm.DB, error), baseTableName string, fields []string, entityGroupKeyMapping map[string]string) ([]*domain.SummaryUnique, error) {
	ret := make([]*domain.SummaryUnique, 0, len(fields))
	if len(fields) == 0 {
		return ret, nil
	}
	eg, _ := errgroup.WithContext(ctx)
	mu := &sync.Mutex{}
	for _, field := range fields {
		field := field
		eg.Go(func() error {
			sq := &domain.SummaryUnique{Field: field}
			vs := strings.Split(field, ".")
			if len(vs) != 2 {
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
			// TODO add column validation. e,g. grants.unknown_column is not valid column.

			cm := fmt.Sprintf("%q.%q", tableName, columnName)
			db, err := dbGen()
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

func generateGroupSummaries(_ context.Context, dbGen func() (*gorm.DB, error), baseTableName string, fields []string, entityGroupKeyMapping map[string]string) ([]*domain.SummaryGroup, error) {
	sg := make([]*domain.SummaryGroup, 0)
	if len(fields) == 0 {
		return sg, nil
	}

	db, err := dbGen()
	if err != nil {
		return nil, err
	}

	const countColumnAlias = "count"
	selectCols, groupCols := make([]string, len(fields)), make([]string, len(fields))

	for i, field := range fields {
		vs := strings.Split(field, ".")
		if len(vs) != 2 {
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
		selectCols[i] = fmt.Sprintf("%s AS %q", cm, field)
		groupCols[i] = fmt.Sprintf("%q", field)
	}
	selectCols = append(selectCols, fmt.Sprintf("COUNT(1) AS %s", countColumnAlias))

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
		var count int32
		for i, col := range cols {
			groupValues := values[:i]
			val := values[i]
			switch col {
			case countColumnAlias:
				intValue, err := strconv.Atoi(fmt.Sprint(val))
				if err != nil {
					return nil, fmt.Errorf("invalid count value (%T) for group values: %v", val, groupValues)
				}
				count = int32(intValue)
			default:
				groupFields[col] = val
			}
		}
		sg = append(sg, &domain.SummaryGroup{
			GroupFields: groupFields,
			Count:       count,
		})
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
	return &domain.SummaryResult{
		SummaryGroups:  result.SummaryGroups,
		SummaryUniques: result.SummaryUniques,
		GroupsCount:    groupsCount,
		UniquesCount:   uniquesCount,
	}
}
