package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"sort"
	"strings"
	"time"

	"github.com/goto/guardian/domain"
	"gorm.io/gorm"
)

type NotificationCardRepository struct{ db *gorm.DB }

func NewNotificationCardRepository(db *gorm.DB) *NotificationCardRepository {
	return &NotificationCardRepository{db: db}
}

func (r *NotificationCardRepository) Ready(ctx context.Context) error {
	return r.db.WithContext(ctx).Exec("SELECT event_id FROM notification_card_receipts LIMIT 0").Error
}

func (r *NotificationCardRepository) Prepare(ctx context.Context, card domain.NotificationCard, lease time.Duration) error {
	ids, err := json.Marshal(card.ApprovalIDs)
	if err != nil {
		return errors.New("invalid notification card context")
	}
	return r.db.WithContext(ctx).Exec(`INSERT INTO notification_card_receipts
        (event_id,worker_url,appeal_id,appeal_revision,recipient,approval_ids,last_state_hash,lease_owner,lease_until)
        VALUES (?,?,?,?,?,?::jsonb,?,?::uuid,NOW()+(? * interval '1 second')) ON CONFLICT(event_id) DO NOTHING`,
		card.EventID, card.WorkerURL, card.AppealID, card.Revision, card.Recipient, string(ids), card.LastStateHash, card.EventID, lease.Seconds()).Error
}

func (r *NotificationCardRepository) Confirm(ctx context.Context, eventID, messageID string) error {
	return r.db.WithContext(ctx).Exec(`UPDATE notification_card_receipts SET message_id=?,lease_owner=NULL,lease_until=NULL,next_check_at=NOW(),updated_at=NOW()
        WHERE event_id=? AND (message_id IS NULL OR message_id=?)`, messageID, eventID, messageID).Error
}

func (r *NotificationCardRepository) Claim(ctx context.Context, workerURL, owner string, limit int) ([]domain.NotificationCard, error) {
	type row struct {
		EventID, WorkerURL, MessageID, AppealID, Recipient, LastStateHash string
		AppealRevision                                                    uint32
		ApprovalIDs                                                       json.RawMessage
		DeliveryDeadline                                                  time.Time
		CreatedAt                                                         time.Time
	}
	var rows []row
	err := r.db.WithContext(ctx).Raw(`WITH due AS (
            SELECT event_id FROM notification_card_receipts WHERE worker_url=? AND NOT closed
            AND next_check_at<=NOW() AND (lease_until IS NULL OR lease_until<NOW())
            ORDER BY next_check_at,event_id FOR UPDATE SKIP LOCKED LIMIT ?
        ) UPDATE notification_card_receipts c SET lease_owner=?::uuid,lease_until=NOW()+interval '2 minutes'
        FROM due WHERE c.event_id=due.event_id
        RETURNING c.event_id,c.worker_url,COALESCE(c.message_id,'') AS message_id,c.appeal_id,c.appeal_revision,c.recipient,c.approval_ids,c.last_state_hash,c.delivery_deadline,c.created_at`, workerURL, limit, owner).Scan(&rows).Error
	if err != nil {
		return nil, err
	}
	result := make([]domain.NotificationCard, 0, len(rows))
	for _, v := range rows {
		var ids []string
		if json.Unmarshal(v.ApprovalIDs, &ids) != nil {
			return nil, errors.New("invalid persisted card context")
		}
		result = append(result, domain.NotificationCard{CreatedAt: v.CreatedAt, EventID: v.EventID, WorkerURL: v.WorkerURL, MessageID: v.MessageID, AppealID: v.AppealID, Revision: v.AppealRevision, Recipient: v.Recipient, ApprovalIDs: ids, LastStateHash: v.LastStateHash, DeliveryDeadline: v.DeliveryDeadline, LeaseOwner: owner})
	}
	return result, nil
}

func (r *NotificationCardRepository) Complete(ctx context.Context, card domain.NotificationCard, hash string, closed bool, delay time.Duration) error {
	return r.db.WithContext(ctx).Exec(`UPDATE notification_card_receipts SET last_state_hash=?,closed=?,next_check_at=NOW()+(? * interval '1 second'),lease_owner=NULL,lease_until=NULL,updated_at=NOW()
        WHERE event_id=? AND lease_owner=?::uuid`, hash, closed, delay.Seconds(), card.EventID, card.LeaseOwner).Error
}

func (r *NotificationCardRepository) Retry(ctx context.Context, card domain.NotificationCard, delay time.Duration) error {
	return r.db.WithContext(ctx).Exec(`UPDATE notification_card_receipts SET next_check_at=NOW()+(? * interval '1 second'),lease_owner=NULL,lease_until=NULL,updated_at=NOW()
        WHERE event_id=? AND lease_owner=?::uuid`, delay.Seconds(), card.EventID, card.LeaseOwner).Error
}

// GetByMessageID reads current saved scope without claiming a reconciliation lease.
func (r *NotificationCardRepository) GetByMessageID(ctx context.Context, messageID string) (*domain.NotificationCard, error) {
	var row struct {
		EventID, WorkerURL, MessageID, AppealID, Recipient string
		AppealRevision                                     uint32
		ApprovalIDs                                        json.RawMessage
		Closed                                             bool
		CreatedAt                                          time.Time
	}
	query := r.db.WithContext(ctx).Raw(`SELECT event_id,worker_url,message_id,appeal_id,appeal_revision,recipient,approval_ids,closed,created_at
 FROM notification_card_receipts WHERE message_id=?`, messageID).Scan(&row)
	if query.Error != nil {
		return nil, query.Error
	}
	if query.RowsAffected == 0 {
		return nil, gorm.ErrRecordNotFound
	}
	var ids []string
	if json.Unmarshal(row.ApprovalIDs, &ids) != nil || len(ids) == 0 {
		return nil, errors.New("invalid persisted card context")
	}
	return &domain.NotificationCard{CreatedAt: row.CreatedAt, EventID: row.EventID, WorkerURL: row.WorkerURL, MessageID: row.MessageID, AppealID: row.AppealID, Revision: row.AppealRevision, Recipient: row.Recipient, ApprovalIDs: ids, Closed: row.Closed}, nil
}

// Ensure serializes initial sends and stage transitions for one recipient/appeal revision.
// Later steps extend stored scope but never reset created_at, delivery_deadline or event_id.
// Callbacks still act only on the IDs encoded in the actual button that was clicked.
func (r *NotificationCardRepository) Ensure(ctx context.Context, card domain.NotificationCard, lease time.Duration) (created bool, err error) {
	card.Recipient = strings.ToLower(strings.TrimSpace(card.Recipient))
	key, _ := json.Marshal([]interface{}{card.WorkerURL, card.AppealID, card.Revision, card.Recipient})
	err = r.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		// Also serialize the no-row-yet case across Guardian processes without changing schema.
		if err := tx.Exec("SELECT pg_advisory_xact_lock(hashtextextended(?,0))", string(key)).Error; err != nil {
			return err
		}
		var existing struct {
			EventID     string
			ApprovalIDs json.RawMessage
			Closed      bool
			CreatedAt   time.Time
		}
		query := tx.Raw(`SELECT event_id,approval_ids,closed,created_at FROM notification_card_receipts
 WHERE worker_url=? AND appeal_id=? AND appeal_revision=? AND lower(trim(recipient))=?
 ORDER BY created_at,event_id LIMIT 1 FOR UPDATE`, card.WorkerURL, card.AppealID, card.Revision, card.Recipient).Scan(&existing)
		if query.Error != nil {
			return query.Error
		}
		if query.RowsAffected == 0 {
			if err := NewNotificationCardRepository(tx).Prepare(ctx, card, lease); err != nil {
				return err
			}
			created = true
			return nil
		}
		if existing.Closed || (domain.NotificationCard{CreatedAt: existing.CreatedAt}).Expired(time.Now()) {
			return nil
		}
		var ids []string
		if err := json.Unmarshal(existing.ApprovalIDs, &ids); err != nil {
			return errors.New("invalid persisted card context")
		}
		seen := map[string]bool{}
		for _, id := range ids {
			seen[id] = true
		}
		changed := false
		for _, id := range card.ApprovalIDs {
			if !seen[id] {
				ids = append(ids, id)
				seen[id] = true
				changed = true
			}
		}
		if !changed {
			return nil
		}
		sort.Strings(ids)
		encoded, _ := json.Marshal(ids)
		// Invalidate older reconciliation leases, so their completion cannot erase this refresh.
		return tx.Exec(`UPDATE notification_card_receipts SET approval_ids=?::jsonb,last_state_hash='',
 next_check_at=NOW(),lease_owner=NULL,lease_until=NULL,updated_at=NOW() WHERE event_id=?`, string(encoded), existing.EventID).Error
	})
	return created, err
}
