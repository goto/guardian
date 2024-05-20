package postgres

import (
	"context"
	"errors"

	"github.com/goto/guardian/domain"
	"github.com/goto/salt/audit"
	auditrepo "github.com/goto/salt/audit/repositories"
	"gorm.io/gorm"
)

type eventModel auditrepo.AuditModel

func (m *eventModel) toDomain(domainEvent *audit.Log) error {
	if m == nil {
		return nil
	}

	if domainEvent == nil {
		return errors.New("domain.Event is nil")
	}

	domainEvent.Timestamp = m.Timestamp
	domainEvent.Action = m.Action
	domainEvent.Actor = m.Actor

	if m.Data.Valid {
		data := make(map[string]interface{})
		if err := m.Data.Unmarshal(&data); err != nil {
			return err
		}
		domainEvent.Data = data
	}

	return nil
}

func (m *eventModel) TableName() string {
	return "audit_logs"
}

// TODO: merge into github.com/goto/salt/audit
type AuditLogRepository struct {
	db *gorm.DB
}

func NewAuditLogRepository(db *gorm.DB) *AuditLogRepository {
	return &AuditLogRepository{db: db}
}

func (r *AuditLogRepository) List(ctx context.Context, filter *domain.ListAuditLogFilter) ([]*audit.Log, error) {
	db := r.db.WithContext(ctx)

	if filter != nil {
		if filter.Actions != nil {
			db = db.Where(`"action" IN ?`, filter.Actions)
		}
		if filter.AppealID != "" {
			db = db.Where(`"data" ->> 'appeal_id' = ?`, filter.AppealID)
		}
	}
	db = db.Order("timestamp DESC")

	records := []*eventModel{}
	if err := db.Find(&records).Error; err != nil {
		return nil, err
	}

	events := make([]*audit.Log, 0, len(records))
	for _, record := range records {
		a := new(audit.Log)
		if err := record.toDomain(a); err != nil {
			return nil, err
		}
		events = append(events, a)
	}

	return events, nil
}
