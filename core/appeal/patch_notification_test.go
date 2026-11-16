package appeal_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/goto/guardian/core/appeal"
	"github.com/goto/guardian/domain"
	"github.com/goto/guardian/plugins/notifiers/larkv2"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

func TestPatchNotifiesWithPersistedRevisionAndAnswers(t *testing.T) {
	for _, answers := range []map[string]interface{}{
		{"business_reason": "Investigate updated dashboard", "ticket": "DATA-123"},
		{"business_reason": "", "ticket": "  "},
	} {
		t.Run("optional_answers_"+answers["business_reason"].(string), func(t *testing.T) {
			h := newServiceTestHelper()
			old := &domain.Appeal{ID: "11111111-1111-4111-8111-111111111111", ResourceID: "resource", Resource: &domain.Resource{ID: "resource", Name: "Dataset", Type: "table", ProviderType: "fixture", ProviderURN: "fixture"}, PolicyID: "policy", PolicyVersion: 1, Status: "pending", AccountID: "requester@example.com", CreatedBy: "requester@example.com", AccountType: "user", Role: "reader", Options: &domain.AppealOptions{Duration: "24h"}, Revision: 2, Details: map[string]interface{}{"__policy_questions": map[string]interface{}{"business_reason": "Old reason"}}, Approvals: []*domain.Approval{{ID: "old-step", Name: "owner", Status: "pending", AppealRevision: 2, Approvers: []string{"old@example.com"}}}}
			pc := &domain.Provider{ID: "provider", Type: "fixture", URN: "fixture", Config: &domain.ProviderConfig{Resources: []*domain.ResourceConfig{{Type: "table", Policy: &domain.PolicyConfig{ID: "policy", Version: 1}, Roles: []*domain.Role{{ID: "reader", Permissions: []interface{}{"read"}}}}}}}
			policy := &domain.Policy{ID: "policy", Version: 1, AppealConfig: &domain.PolicyAppealConfig{DurationOptions: []domain.AppealDurationOption{{Name: "Day", Value: "24h"}}}, Steps: []*domain.Step{{Name: "owner", Strategy: "manual", Approvers: []string{"new@example.com"}}, {Name: "manager", Strategy: "manual", Approvers: []string{"later@example.com"}}}}
			h.mockRepository.EXPECT().GetByID(mock.Anything, old.ID).Return(old, nil).Once()
			h.mockProviderService.EXPECT().Find(mock.Anything, mock.Anything).Return([]*domain.Provider{pc}, nil).Once()
			h.mockPolicyService.EXPECT().Find(mock.Anything, mock.Anything).Return([]*domain.Policy{policy}, nil).Once()
			h.mockRepository.EXPECT().Find(mock.Anything, mock.Anything).Return([]*domain.Appeal{}, nil).Once()
			h.mockGrantService.EXPECT().List(mock.Anything, mock.Anything).Return([]domain.Grant{}, nil).Once()
			h.mockProviderService.EXPECT().ValidateAppeal(mock.Anything, mock.Anything, pc, policy).Return(nil).Once()
			h.mockProviderService.EXPECT().GetPermissions(mock.Anything, mock.Anything, "table", "reader").Return([]interface{}{"read"}, nil).Once()
			h.mockRepository.EXPECT().UpdateByID(mock.Anything, mock.Anything).Run(func(_ context.Context, a *domain.Appeal) {
				// Match the real repository: model conversion replaces pointers and
				// newly inserted approvals receive IDs only in the saved objects.
				data, err := json.Marshal(a)
				require.NoError(t, err)
				var saved domain.Appeal
				require.NoError(t, json.Unmarshal(data, &saved))
				for _, step := range saved.Approvals {
					if !step.IsStale {
						step.ID = "saved-" + step.Name
					}
				}
				*a = saved
			}).Return(nil).Once()
			h.mockAuditLogger.EXPECT().Log(mock.Anything, appeal.AuditKeyUpdate, mock.Anything).Return(nil).Once()
			delivered := make(chan []domain.Notification, 1)
			h.mockNotifier.EXPECT().Notify(mock.Anything, mock.Anything).Run(func(_ context.Context, n []domain.Notification) { delivered <- n }).Return(nil).Once()
			request := &domain.Appeal{ID: old.ID, Details: map[string]interface{}{"__policy_questions": answers}}
			require.NoError(t, h.service.Patch(context.Background(), request))
			var batch []domain.Notification
			select {
			case batch = <-delivered:
			case <-time.After(time.Second):
				t.Fatal("notification missing")
			}
			require.Len(t, batch, 1)
			require.Equal(t, "new@example.com", batch[0].User)
			require.Equal(t, "saved-owner", batch[0].Approval.ApprovalID)
			require.EqualValues(t, 3, batch[0].Approval.Revision)
			require.Len(t, request.Approvals, 2)
			for _, step := range request.Approvals {
				require.False(t, step.IsStale)
				require.NotEmpty(t, step.ID)
				require.EqualValues(t, 3, step.AppealRevision)
			}
			// Exercise the actual v2 wire adapter too: the empty-ID regression
			// previously stopped here before any worker request could be sent.
			calls := 0
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls++
				var body struct {
					EventID   string                       `json:"event_id"`
					Approval  *domain.NotificationApproval `json:"approval"`
					Variables map[string]interface{}       `json:"variables"`
				}
				require.NoError(t, json.NewDecoder(r.Body).Decode(&body))
				require.Equal(t, "saved-owner", body.Approval.ApprovalID)
				require.Equal(t, domain.NotificationQuestionAnswers(answers), func() map[string]string {
					m := map[string]string{}
					for k, v := range body.Variables["policy_questions"].(map[string]interface{}) {
						m[k] = v.(string)
					}
					return m
				}())
				_ = json.NewEncoder(w).Encode(map[string]string{"event_id": body.EventID, "message_id": "om_saved", "bot": "pending"})
			}))
			defer server.Close()
			n, err := larkv2.New(larkv2.Config{URL: server.URL})
			require.NoError(t, err)
			require.Empty(t, n.Notify(context.Background(), batch))
			require.Equal(t, 1, calls)
			h.assertExpectations(t)
		})
	}
}
