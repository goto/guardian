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
}

func addOrderByClause(db *gorm.DB, conditions []string, options addOrderByClauseOptions) *gorm.DB {
	var orderByClauses []string
	var vars []interface{}

	for _, orderBy := range conditions {
		if strings.Contains(orderBy, "status") {
			orderByClauses = append(orderByClauses, fmt.Sprintf(`ARRAY_POSITION(ARRAY[?], %s)`, options.statusColumnName))
			vars = append(vars, options.statusesOrder)
		} else {
			columnOrder := strings.Split(orderBy, ":")
			column := columnOrder[0]
			if utils.ContainsString([]string{"updated_at", "created_at"}, column) {
				if len(columnOrder) == 1 {
					orderByClauses = append(orderByClauses, fmt.Sprintf(`"%s"`, column))
				} else if len(columnOrder) == 2 {
					order := columnOrder[1]
					if utils.ContainsString([]string{"asc", "desc"}, order) {
						orderByClauses = append(orderByClauses, fmt.Sprintf(`"%s" %s`, column, order))
					}
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
	})
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
