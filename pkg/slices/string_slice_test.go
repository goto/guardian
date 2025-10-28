package slices_test

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/goto/guardian/pkg/slices"
)

func TestUniqueStringSlice(t *testing.T) {
	testCases := []struct {
		name     string
		input    []string
		expected []string
	}{
		{
			name:     "nil",
			input:    nil,
			expected: nil,
		},
		{
			name:     "empty",
			input:    []string{},
			expected: []string{},
		},
		{
			name:     "one",
			input:    []string{"a"},
			expected: []string{"a"},
		},
		{
			name:     "double b",
			input:    []string{"a", "b", "b"},
			expected: []string{"a", "b"},
		},
		{
			name:     "double c",
			input:    []string{"c", "b", "c"},
			expected: []string{"c", "b"},
		},
		{
			name:     "complex",
			input:    []string{"b", "b", "c", "a", "b", "c", "a", "b", "c"},
			expected: []string{"b", "c", "a"},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			actual := slices.UniqueStringSlice(tc.input)
			assert.Equal(t, tc.expected, actual)
		})
	}
}

func TestToLowerStringSlice(t *testing.T) {
	testCases := []struct {
		name     string
		input    []string
		expected []string
	}{
		{
			name:     "nil",
			input:    nil,
			expected: nil,
		},
		{
			name:     "empty",
			input:    []string{},
			expected: []string{},
		},
		{
			name:     "already lowercase",
			input:    []string{"a", "b", "c"},
			expected: []string{"a", "b", "c"},
		},
		{
			name:     "mixed case",
			input:    []string{"A", "b", "C"},
			expected: []string{"a", "b", "c"},
		},
		{
			name:     "all uppercase",
			input:    []string{"HELLO", "WORLD"},
			expected: []string{"hello", "world"},
		},
		{
			name:     "with symbols",
			input:    []string{"TeSt-1", "FOO_BAR"},
			expected: []string{"test-1", "foo_bar"},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			actual := slices.ToLowerStringSlice(tc.input)
			assert.Equal(t, tc.expected, actual)
		})
	}
}
