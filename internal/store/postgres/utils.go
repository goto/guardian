package postgres

import (
	"fmt"
	"strings"

	"github.com/goto/guardian/utils"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
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
					orderByClauses = append(orderByClauses, fmt.Sprintf(`(CASE WHEN "%s" = '%s' THEN 1 ELSE 2 END)`, strings.ToLower(columnName), strings.ToLower(options.searchQuery)))
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
