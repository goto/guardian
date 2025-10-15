package postgres

import (
	"context"
	"fmt"
	"strconv"
	"strings"

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

func addOrderByClauseWithBaseTableName(db *gorm.DB, conditions []string, options addOrderByClauseOptions, allowedColumns []string, baseTableName string) (*gorm.DB, error) {
	var orderByClauses []string
	var vars []interface{}

	for _, orderBy := range conditions {
		if strings.Contains(orderBy, "status") {
			orderByClauses = append(orderByClauses, fmt.Sprintf(`ARRAY_POSITION(ARRAY[?], "%s"."%s")`, baseTableName, options.statusColumnName))
			vars = append(vars, options.statusesOrder)
		} else {
			columnOrder := strings.Split(orderBy, ":")
			columnName := columnOrder[0]
			if !utils.ContainsString(allowedColumns, columnName) {
				return nil, fmt.Errorf("cannot order by column %q", columnName)
			}
			if len(columnOrder) == 1 {
				orderByClauses = append(orderByClauses, fmt.Sprintf(`"%s"."%s"`, baseTableName, columnName))
			} else if len(columnOrder) == 2 {
				orderDirection := columnOrder[1]
				if utils.ContainsString([]string{"asc", "desc"}, orderDirection) {
					orderByClauses = append(orderByClauses, fmt.Sprintf(`"%s"."%s" %s`, baseTableName, columnName, orderDirection))
				} else if orderDirection == "exact_asc" && columnName == "name" {
					orderByClauses = append(orderByClauses, fmt.Sprintf(`(CASE WHEN lower("%s"."%s") = '%s' THEN 1 ELSE 2 END)`, baseTableName, columnName, strings.ToLower(options.searchQuery)))
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

func generateSummary(_ context.Context, db *gorm.DB, baseTableName string, groupBys []string, entityGroupKeyMapping map[string]string) (*domain.SummaryResult, error) {
	const countColumnAlias = "count"
	var selectCols []string
	var groupCols []string

	// TODO | https://github.com/goto/guardian/pull/218#discussion_r2336292684
	// Add validation for group bys. e,g. filter to group by 'created_at' since it not make sense.
	for _, groupKey := range groupBys {
		var column string
		for i, field := range strings.Split(groupKey, ".") {
			if i == 0 {
				tableName, ok := entityGroupKeyMapping[field]
				if !ok {
					return nil, fmt.Errorf("%w %q", domain.ErrInvalidGroupByField, field)
				}
				column = fmt.Sprintf("%q", tableName)
				continue
			}

			column += "." + fmt.Sprintf("%q", field)
		}

		selectCols = append(selectCols, fmt.Sprintf(`%s AS %q`, column, groupKey))
		groupCols = append(groupCols, fmt.Sprintf("%q", groupKey))
	}
	selectCols = append(selectCols, fmt.Sprintf("COUNT(1) AS %s", countColumnAlias))

	db = db.Table(baseTableName).Select(strings.Join(selectCols, ", "))
	if len(groupBys) > 0 {
		db = db.Group(strings.Join(groupCols, ", "))
	}

	// Execute query
	rows, err := db.Rows()
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	result := &domain.SummaryResult{
		SummaryGroups: []*domain.SummaryGroup{},
		Count:         0,
	}

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

		if err := rows.Scan(valuePtrs...); err != nil {
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
		if len(groupBys) > 0 {
			result.SummaryGroups = append(result.SummaryGroups, &domain.SummaryGroup{
				GroupFields: groupFields,
				Count:       count,
			})
		}
		result.Count += count
	}
	return result, nil
}
