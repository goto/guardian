package postgres_test

import (
	"context"
	"errors"
	"os"
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
	if err != nil || saved == nil || saved.AppealID != appealID || saved.Revision != 2 || saved.Recipient != "b@example.com" || len(saved.ApprovalIDs) != 1 || saved.ApprovalIDs[0] != "approval-1" || saved.Closed {
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
	if claimed[0].MessageID != "om_b" || claimed[0].Recipient != "b@example.com" || len(claimed[0].ApprovalIDs) != 1 || claimed[0].Revision != 2 {
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
	if err := store.DB().Exec("DELETE FROM appeals WHERE id=?", appealID).Error; err != nil {
		t.Fatal(err)
	}
	var count int64
	store.DB().Table("notification_card_receipts").Count(&count)
	if count != 0 {
		t.Fatal("deleted appeal retained card receipts")
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
