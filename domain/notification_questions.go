package domain

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
)

// NotificationQuestionAnswers projects only answered policy questions. Internal
// metadata and nested objects are never interpreted as approver-facing prose.
// Keep normalization in sync with the worker's questionAnswers function.
func NotificationQuestionAnswers(questions map[string]interface{}) map[string]string {
	result := map[string]string{}
	keys := make([]string, 0, len(questions))
	for key := range questions {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, original := range keys {
		key := strings.TrimSpace(original)
		if key == "" {
			continue
		}
		var answer string
		switch v := questions[original].(type) {
		case string:
			answer = v
		case bool, float64, float32, int, int64, json.Number:
			answer = fmt.Sprint(v)
		case []string:
			var parts []string
			for _, item := range v {
				if item = strings.TrimSpace(item); item != "" {
					parts = append(parts, item)
				}
			}
			answer = strings.Join(parts, ", ")
		case []interface{}:
			var parts []string
			for _, item := range v {
				if s, ok := item.(string); ok && strings.TrimSpace(s) != "" {
					parts = append(parts, strings.TrimSpace(s))
				}
			}
			answer = strings.Join(parts, ", ")
		}
		answer = strings.TrimSpace(answer)
		if answer != "" && result[key] == "" {
			result[key] = answer
		}
	}
	return result
}
