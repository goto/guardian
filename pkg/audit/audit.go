package audit

import "context"

type AuditLogger interface {
	Log(ctx context.Context, action string, data interface{}) error
}
