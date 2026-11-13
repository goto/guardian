package appeal

import (
	"github.com/goto/guardian/domain"
	"testing"
	"time"
)

func TestNotificationExpiryUsesCommittedGrant(t *testing.T) {
	expires := time.Date(2027, 2, 11, 5, 22, 0, 0, time.UTC)
	requested := expires.Add(-time.Hour)
	a := &domain.Appeal{Status: "approved", Options: &domain.AppealOptions{Duration: "24h", ExpirationDate: &requested}, Grant: &domain.Grant{ExpirationDate: &expires}}
	if got := notificationExpiration(a); got == nil || !got.Equal(expires) {
		t.Fatal("actual grant expiry not used")
	}
	a.Status = "pending"
	if notificationExpiration(a) != nil {
		t.Fatal("pending request has an actual expiry")
	}
	a.Status = "approved"
	a.Grant.IsPermanent = true
	if notificationExpiration(a) != nil {
		t.Fatal("permanent grant shown as expiring")
	}
}
