package postgres_test

import (
	"context"
	"errors"
	"fmt"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/goto/guardian/domain"
	"github.com/goto/guardian/internal/store/postgres"
	"github.com/goto/guardian/pkg/log"
	"github.com/goto/guardian/pkg/postgrestest"
	"gorm.io/gorm"
)

func TestNotificationCardRepositoryPersistenceLeasesAndMigration(t *testing.T) {
	if testing.Short() {
		t.Skip("requires owned disposable PostgreSQL")
	}
	store, pool, resource, err := postgrestest.NewTestStore(log.NewNoop())
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		db, _ := store.DB().DB()
		_ = db.Close()
		if err := postgrestest.PurgeTestDocker(pool, resource); err != nil {
			t.Error(err)
		}
	}()
	ctx := context.Background()
	repo := postgres.NewNotificationCardRepository(store.DB())
	if err := repo.Ready(ctx); err != nil {
		t.Fatal(err)
	}
	appealID := uuid.NewString()
	if err := store.DB().Exec("INSERT INTO appeals(id,status,revision,permissions) VALUES (?,'pending',2,'{}'::text[])", appealID).Error; err != nil {
		t.Fatal(err)
	}
	card := domain.NotificationCard{EventID: uuid.NewString(), WorkerURL: "http://worker.example.com", AppealID: appealID, Revision: 2, Recipient: "b@example.com", ApprovalIDs: []string{"approval-1"}, LastStateHash: "pending"}
	if err := repo.Prepare(ctx, card, 0); err != nil {
		t.Fatal(err)
	}
	if err := repo.Prepare(ctx, card, 0); err != nil {
		t.Fatal("prepare is not idempotent:", err)
	}
	if err := repo.Confirm(ctx, card.EventID, "om_b"); err != nil {
		t.Fatal(err)
	}
	saved, err := repo.GetByMessageID(ctx, "om_b")
	if err != nil || saved == nil || saved.CreatedAt.IsZero() || saved.AppealID != appealID || saved.Revision != 2 || saved.Recipient != "b@example.com" || len(saved.ApprovalIDs) != 1 || saved.ApprovalIDs[0] != "approval-1" || saved.Closed {
		t.Fatalf("receipt lookup lost immutable scope: %+v %v", saved, err)
	}
	if _, err := repo.GetByMessageID(ctx, "om_unknown"); !errors.Is(err, gorm.ErrRecordNotFound) {
		t.Fatal("unknown card has a receipt")
	}
	owner := uuid.NewString()
	claimed, err := repo.Claim(ctx, card.WorkerURL, owner, 10)
	if err != nil || len(claimed) != 1 {
		t.Fatalf("claim: %+v %v", claimed, err)
	}
	if claimed[0].CreatedAt.IsZero() || claimed[0].MessageID != "om_b" || claimed[0].Recipient != "b@example.com" || len(claimed[0].ApprovalIDs) != 1 || claimed[0].Revision != 2 {
		t.Fatal("receipt did not survive round trip")
	}
	other, err := repo.Claim(ctx, card.WorkerURL, uuid.NewString(), 10)
	if err != nil || len(other) != 0 {
		t.Fatal("two processes claimed the same card")
	}
	stale := claimed[0]
	stale.LeaseOwner = uuid.NewString()
	if err := repo.Complete(ctx, stale, "wrong", true, 0); err != nil {
		t.Fatal(err)
	}
	if err := repo.Complete(ctx, claimed[0], "approved", false, 0); err != nil {
		t.Fatal(err)
	}
	restarted := postgres.NewNotificationCardRepository(store.DB())
	again, err := restarted.Claim(ctx, card.WorkerURL, uuid.NewString(), 10)
	if err != nil || len(again) != 1 || again[0].LastStateHash != "approved" || again[0].MessageID != "om_b" {
		t.Fatalf("restart lost metadata or stale lease overwrote state: %+v %v", again, err)
	}
	if err := store.DB().Exec("UPDATE notification_card_receipts SET lease_until=NOW()-interval '1 second' WHERE event_id=?", card.EventID).Error; err != nil {
		t.Fatal(err)
	}
	recovered, err := repo.Claim(ctx, card.WorkerURL, uuid.NewString(), 10)
	if err != nil || len(recovered) != 1 {
		t.Fatal("crashed owner lease did not recover")
	}
	if err := repo.Complete(ctx, recovered[0], "approved", true, time.Second); err != nil {
		t.Fatal(err)
	}
	closedCard, err := repo.GetByMessageID(ctx, "om_b")
	if err != nil || !closedCard.Closed || closedCard.ApprovalIDs[0] != "approval-1" {
		t.Fatal("closed receipt lost stored scope")
	}
	if cards, err := repo.Claim(ctx, card.WorkerURL, uuid.NewString(), 10); err != nil || len(cards) != 0 {
		t.Fatal("closed card was reclaimed")
	}
	// An unresolved recipient is closed using the initial sender's existing
	// event-ID lease, without creating a message ID or a new persistence model.
	skipped := card
	skipped.EventID = uuid.NewString()
	skipped.Recipient = "missing@example.com"
	skipped.MessageID = ""
	skipped.LeaseOwner = skipped.EventID
	if created, err := repo.Ensure(ctx, skipped, time.Minute); err != nil || !created {
		t.Fatalf("prepare skipped delivery: created=%v err=%v", created, err)
	}
	if err := repo.Complete(ctx, skipped, skipped.LastStateHash, true, 0); err != nil {
		t.Fatal(err)
	}
	var closed bool
	if err := store.DB().Raw("SELECT closed FROM notification_card_receipts WHERE event_id=?", skipped.EventID).Scan(&closed).Error; err != nil || !closed {
		t.Fatalf("initial lease did not close skip: %v", err)
	}
	skipped.EventID = uuid.NewString()
	skipped.ApprovalIDs = []string{"later-approval"}
	if created, err := repo.Ensure(ctx, skipped, time.Minute); err != nil || created {
		t.Fatal("later stage reopened skipped recipient")
	}
	if err := store.DB().Exec("DELETE FROM appeals WHERE id=?", appealID).Error; err != nil {
		t.Fatal(err)
	}
	var count int64
	store.DB().Table("notification_card_receipts").Count(&count)
	if count != 0 {
		t.Fatal("deleted appeal retained card receipts")
	}
	// Concurrent producers and later stages must share one original receipt, even across restarts.
	reuseID := uuid.NewString()
	if err := store.DB().Exec("INSERT INTO appeals(id,status,revision,permissions) VALUES (?,'pending',2,'{}'::text[])", reuseID).Error; err != nil {
		t.Fatal(err)
	}
	var createdCount atomic.Int32
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			c := card
			c.EventID = uuid.NewString()
			c.AppealID = reuseID
			c.ApprovalIDs = []string{fmt.Sprintf("step-%d", i)}
			created, err := repo.Ensure(ctx, c, 0)
			if err != nil {
				t.Error(err)
			}
			if created {
				createdCount.Add(1)
			}
		}(i)
	}
	wg.Wait()
	var rows []domain.NotificationCard
	// Read through the public claim/lookup paths rather than trusting helper return values.
	rows, err = repo.Claim(ctx, card.WorkerURL, uuid.NewString(), 10)
	if err != nil || createdCount.Load() != 1 || len(rows) != 1 || len(rows[0].ApprovalIDs) != 8 {
		t.Fatalf("concurrent ensure lost/duplicated scope: %+v %v", rows, err)
	}
	original := rows[0]
	if err := repo.Confirm(ctx, original.EventID, "om_reuse"); err != nil {
		t.Fatal(err)
	}
	leased, err := repo.Claim(ctx, card.WorkerURL, uuid.NewString(), 10)
	if err != nil || len(leased) != 1 {
		t.Fatal("claim original")
	}
	later := card
	later.EventID = uuid.NewString()
	later.AppealID = reuseID
	later.Recipient = " B@EXAMPLE.COM "
	later.ApprovalIDs = []string{"later"}
	if created, err := restarted.Ensure(ctx, later, 0); err != nil || created {
		t.Fatal("later stage created another receipt")
	}
	if err := repo.Complete(ctx, leased[0], "stale", true, 0); err != nil {
		t.Fatal(err)
	}
	merged, err := repo.GetByMessageID(ctx, "om_reuse")
	if err != nil || merged.Closed || len(merged.ApprovalIDs) != 9 || !merged.CreatedAt.Equal(original.CreatedAt) {
		t.Fatal("stale lease erased expansion or original age")
	}
	var hash string
	store.DB().Raw("SELECT last_state_hash FROM notification_card_receipts WHERE event_id=?", original.EventID).Scan(&hash)
	if hash != "" {
		t.Fatal("scope expansion was not scheduled for repaint")
	}
	if err := store.DB().Exec("UPDATE notification_card_receipts SET created_at=? WHERE event_id=?", time.Now().Add(-13*24*time.Hour-time.Minute), original.EventID).Error; err != nil {
		t.Fatal(err)
	}
	later.ApprovalIDs = []string{"expired-later"}
	if created, err := repo.Ensure(ctx, later, 0); err != nil || created {
		t.Fatal("expired receipt replaced")
	}
	aged, _ := repo.GetByMessageID(ctx, "om_reuse")
	if len(aged.ApprovalIDs) != 9 || !aged.Expired(time.Now()) {
		t.Fatal("expiry age/scope changed")
	}
	if err := store.DB().Exec("DELETE FROM appeals WHERE id=?", reuseID).Error; err != nil {
		t.Fatal(err)
	}
	// Verify down/up compatibility only on this owned disposable database.
	for _, name := range []string{"migrations/000036_create_notification_card_receipts.down.sql", "migrations/000036_create_notification_card_receipts.up.sql"} {
		data, err := os.ReadFile(name)
		if err != nil {
			t.Fatal(err)
		}
		if err := store.DB().Exec(string(data)).Error; err != nil {
			t.Fatal(err)
		}
	}
	if err := repo.Ready(ctx); err != nil {
		t.Fatal(err)
	}
	// The completion retry relies on the repository aborting before saving callback mutations.
	rollbackID := uuid.NewString()
	store.DB().Exec("INSERT INTO appeals(id,status,revision,permissions,labels) VALUES (?,'pending',0,'{}'::text[],'{}'::jsonb)", rollbackID)
	appeals := postgres.NewAppealRepository(store.DB())
	sentinel := errors.New("retry after fresh snapshot")
	_, err = appeals.UpdateWithLock(ctx, rollbackID, nil, func(a *domain.Appeal) error { a.Status = domain.AppealStatusApproved; return sentinel })
	if !errors.Is(err, sentinel) {
		t.Fatalf("callback abort lost error: %v", err)
	}
	var status string
	store.DB().Raw("SELECT status FROM appeals WHERE id=?", rollbackID).Scan(&status)
	if status != "pending" {
		t.Fatal("aborted completion callback persisted Approved")
	}
}
