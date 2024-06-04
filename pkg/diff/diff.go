package diff

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	"github.com/wI2L/jsondiff"
)

type PatchOp struct {
	Op       string      `json:"op"`
	Actor    string      `json:"actor"`
	Path     string      `json:"path"`
	NewValue interface{} `json:"new_value,omitempty"`
	OldValue interface{} `json:"old_value,omitempty"`
}

func GetChangelog(a, b interface{}) ([]PatchOp, error) {
	jsonA, err := json.Marshal(a)
	if err != nil {
		return nil, err
	}

	jsonB, err := json.Marshal(b)
	if err != nil {
		return nil, err
	}

	diff, err := jsondiff.CompareJSON(jsonA, jsonB)
	if err != nil {
		return nil, err
	}

	var originalMap interface{}
	err = json.Unmarshal(jsonA, &originalMap)
	if err != nil {
		return nil, err
	}

	patchWithOldValues := []PatchOp{}

	for _, op := range diff {
		patchOp := PatchOp{
			Op:       op.Type,
			Path:     op.Path,
			NewValue: op.Value,
		}

		if op.Type == "remove" || op.Type == "replace" {
			oldValue, err := getOldValue(originalMap, op.Path)
			if err != nil {
				return nil, err
			}
			patchOp.OldValue = oldValue
		}

		patchWithOldValues = append(patchWithOldValues, patchOp)
	}

	return patchWithOldValues, nil
}

func getOldValue(original interface{}, path string) (interface{}, error) {
	parts := parseJSONPointer(path)
	var current interface{} = original

	for _, part := range parts {
		switch curr := current.(type) {
		case map[string]interface{}:
			current = curr[part]
		case []interface{}:
			index, err := strconv.Atoi(part)
			if err != nil {
				return nil, fmt.Errorf("invalid array index: %s", part)
			}
			if index < 0 || index >= len(curr) {
				return nil, fmt.Errorf("index out of range: %d", index)
			}
			current = curr[index]
		default:
			return nil, fmt.Errorf("invalid path: %s", path)
		}
	}

	return current, nil
}

func parseJSONPointer(path string) []string {
	if path == "" {
		return []string{}
	}

	// Remove leading '/' and split by '/'
	parts := strings.Split(path[1:], "/")
	for i := range parts {
		// Unescape ~1 to / and ~0 to ~ as per RFC 6901
		parts[i] = strings.ReplaceAll(parts[i], "~1", "/")
		parts[i] = strings.ReplaceAll(parts[i], "~0", "~")
	}
	return parts
}
