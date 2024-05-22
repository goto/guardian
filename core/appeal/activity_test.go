package appeal_test

import (
	"context"
	"testing"

	"github.com/goto/guardian/core/appeal"
	"github.com/goto/guardian/domain"
	"github.com/goto/salt/audit"
	"github.com/stretchr/testify/assert"
)

func TestListActivities(t *testing.T) {
	h := newServiceTestHelper()
	defer h.assertExpectations(t)

	appealID := "test-appeal-id"

	dummyAuditLogs := []*audit.Log{
		{
			Timestamp: h.now,
			Action:    appeal.AuditKeyCancel,
			Actor:     "user@example.com",
			Data: map[string]interface{}{
				"appeal_id": appealID,
			},
		},
	}
	h.mockAuditLogRepo.EXPECT().List(h.ctxMatcher, &domain.ListAuditLogFilter{
		Actions: []string{
			appeal.AuditKeyCancel,
			appeal.AuditKeyApprove,
			appeal.AuditKeyReject,
			appeal.AuditKeyAddApprover,
			appeal.AuditKeyDeleteApprover,
		},
		AppealID: appealID,
	}).Return(dummyAuditLogs, nil)
	expectedActivities := []*domain.Event{
		{
			ParentType: "appeal",
			ParentID:   appealID,
			Timestamp:  h.now,
			Type:       appeal.AuditKeyCancel,
			Actor:      "user@example.com",
			Data:       map[string]interface{}{"appeal_id": appealID},
		},
	}

	actualActivities, err := h.service.ListActivities(context.Background(), appealID)
	assert.NoError(t, err)
	assert.Equal(t, expectedActivities, actualActivities)
}
