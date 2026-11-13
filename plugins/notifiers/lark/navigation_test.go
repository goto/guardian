package lark

import (
	"encoding/json"
	"testing"

	"github.com/goto/guardian/domain"
)

func TestUnusedGrantDefaultTemplateIsSupportedAndValid(t *testing.T) {
	msg := domain.NotificationMessage{Type: domain.NotificationTypeUnusedGrant, Variables: map[string]interface{}{
		"start_date_formatted": "Nov 1, 2026", "dormant_grants": []map[string]interface{}{{"id": "grant-1", "account_id": "reader@example.com", "role": "viewer", "expiration_date": "Nov 20, 2026", "resource": map[string]interface{}{"urn": "project.table"}}},
	}}
	data, err := ParseMessage(msg, domain.NotificationMessages{}, defaultTemplates)
	if err != nil {
		t.Fatal(err)
	}
	var messages []struct {
		Content string `json:"content"`
	}
	if err = json.Unmarshal([]byte(data), &messages); err != nil {
		t.Fatal(err)
	}
	if len(messages) != 1 || !json.Valid([]byte(messages[0].Content)) {
		t.Fatal("invalid embedded card JSON")
	}
}
