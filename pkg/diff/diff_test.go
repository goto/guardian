package diff_test

import (
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/goto/guardian/pkg/diff"
	"github.com/stretchr/testify/assert"
)

func TestGetChangelog(t *testing.T) {
	testCases := []struct {
		name     string
		a        any
		b        any
		expected []*diff.PatchOp
	}{
		{
			name: "no diff",
			a: map[string]interface{}{
				"key": "value",
				"int": 1,
			},
			b: map[string]interface{}{
				"key": "value",
				"int": 1,
			},
			expected: nil,
		},
		{
			name: "remove a value",
			a: map[string]interface{}{
				"key": "value",
			},
			b: map[string]interface{}{},
			expected: []*diff.PatchOp{
				{
					Op:       "remove",
					Path:     "key",
					OldValue: "value",
				},
			},
		},
		{
			name: "change value",
			a: map[string]interface{}{
				"bool": true,
				"int":  1,
				"str":  "value",
			},
			b: map[string]interface{}{
				"bool": false,
				"int":  2,
				"str":  "new value",
			},
			expected: []*diff.PatchOp{
				{
					Op:       "replace",
					Path:     "bool",
					OldValue: true,
					NewValue: false,
				},
				{
					Op:       "replace",
					Path:     "int",
					OldValue: float64(1),
					NewValue: float64(2),
				},
				{
					Op:       "replace",
					Path:     "str",
					OldValue: "value",
					NewValue: "new value",
				},
			},
		},
		{
			name: "nested keys",
			a: map[string]interface{}{
				"key": map[string]interface{}{
					"nested_key": "value",
				},
			},
			b: map[string]interface{}{
				"key": map[string]interface{}{
					"nested_key": "new value",
				},
			},
			expected: []*diff.PatchOp{
				{
					Op:       "replace",
					Path:     "key.nested_key",
					OldValue: "value",
					NewValue: "new value",
				},
			},
		},

		// basic slice tests
		{
			name: "slice item addition",
			a:    []string{"a", "b"},
			b:    []string{"a", "b", "c"},
			expected: []*diff.PatchOp{
				{
					Op:       "add",
					Path:     "-",
					NewValue: "c",
				},
			},
		},
		{
			name: "slice item removal",
			a:    []string{"a", "b", "c"},
			b:    []string{"a", "b"},
			expected: []*diff.PatchOp{
				{
					Op:       "remove",
					Path:     "2",
					OldValue: "c",
				},
			},
		},
		{
			name: "slice item change",
			a:    []string{"a", "b", "c"},
			b:    []string{"a", "d", "c"},
			expected: []*diff.PatchOp{
				{
					Op:       "replace",
					Path:     "1",
					OldValue: "b",
					NewValue: "d",
				},
			},
		},

		{
			name: "complex",
			a: map[string]interface{}{
				"details": map[string]interface{}{
					"data": map[string]interface{}{
						"foo": "bar",
						"baz": "qux",
					},
				},
			},
			b: map[string]interface{}{
				"details": map[string]interface{}{
					"data": map[string]interface{}{
						"test": "bar",
						"bazz": "quxx",
					},
				},
			},
			expected: []*diff.PatchOp{
				{
					Op:       "remove",
					Path:     "details.data.baz",
					OldValue: "qux",
				},
				{
					Op:       "add",
					Path:     "details.data.bazz",
					NewValue: "quxx",
				},
				{
					Op:       "remove",
					Path:     "details.data.foo",
					OldValue: "bar",
				},
				{
					Op:       "add",
					Path:     "details.data.test",
					NewValue: "bar",
				},
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			actual, err := diff.GetChangelog(tc.a, tc.b)
			assert.NoError(t, err)
			assert.Empty(t, cmp.Diff(tc.expected, actual, cmpopts.SortSlices(func(a, b *diff.PatchOp) bool {
				return a.Path < b.Path && a.Op < b.Op
			})))
		})
	}
}
