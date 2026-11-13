package report

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	pg "gorm.io/driver/postgres"
	"gorm.io/gorm"
)

func TestReportRowReadFailureIsReturnedBeforeDelivery(t *testing.T) {
	db, m, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	g, err := gorm.Open(pg.New(pg.Config{Conn: db}), &gorm.Config{})
	if err != nil {
		t.Fatal(err)
	}
	rows := sqlmock.NewRows([]string{"appeal_id", "approver", "appeal_created_at"}).AddRow("a", "reviewer@example.com", time.Now()).AddRow("b", "reviewer@example.com", time.Now()).RowError(1, errors.New("synthetic row failure"))
	m.ExpectQuery("SELECT .*approvers.*").WillReturnRows(rows)
	_, err = NewRepository(g).GetPendingApprovalsList(context.Background(), &PendingApprovalsReportFilter{})
	if err == nil {
		t.Fatal("partial report returned success")
	}
	if err = m.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}
