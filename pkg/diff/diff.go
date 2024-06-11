package diff

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/wI2L/jsondiff"
)

type Change struct {
	Op       string
	Path     string
	OldValue any
	NewValue any
}

func Compare(a, b any) ([]*Change, error) {
	jsonA, err := json.Marshal(a)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal a: %w", err)
	}

	jsonB, err := json.Marshal(b)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal b: %w", err)
	}

	diff, err := jsondiff.CompareJSON(jsonA, jsonB)
	if err != nil {
		return nil, err
	}
	if diff == nil {
		return nil, nil
	}

	changes := make([]*Change, 0, len(diff))
	for _, d := range diff {
		changes = append(changes, &Change{
			Op:       d.Type,
			Path:     transformPath(d.Path),
			NewValue: d.Value,
			OldValue: d.OldValue,
		})
	}
	return changes, nil
}

func transformPath(path string) string {
	result := path
	result = strings.TrimPrefix(result, "/")

	// escape . to \.
	result = strings.ReplaceAll(result, ".", "\\.")

	// unescape ~1 to / and ~0 to ~ as per RFC 6901
	result = strings.ReplaceAll(result, "~1", "/")
	result = strings.ReplaceAll(result, "~0", "~")

	// use dot as separator
	result = strings.ReplaceAll(result, "/", ".")
	return result
}
