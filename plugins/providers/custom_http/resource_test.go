package custom_http

import (
	"testing"

	"github.com/goto/guardian/domain"
	"github.com/stretchr/testify/assert"
)

func TestResource_ToDomain(t *testing.T) {
	tests := []struct {
		name     string
		resource Resource
		expected *domain.Resource
	}{
		{
			name: "complete resource conversion",
			resource: Resource{
				ID:   "proj-1",
				Name: "Project 1",
				Type: "project",
				Details: map[string]interface{}{
					"id":          "proj-1",
					"name":        "Project 1",
					"description": "Test project",
					"status":      "active",
				},
			},
			expected: &domain.Resource{
				ID:   "proj-1",
				Name: "Project 1",
				Type: "project",
				URN:  "project:proj-1",
				Details: map[string]interface{}{
					"id":          "proj-1",
					"name":        "Project 1",
					"description": "Test project",
					"status":      "active",
				},
				Children: []*domain.Resource{},
			},
		},
		{
			name: "minimal resource conversion",
			resource: Resource{
				ID:   "db-1",
				Name: "Database 1",
				Type: "database",
				Details: map[string]interface{}{
					"id": "db-1",
				},
			},
			expected: &domain.Resource{
				ID:   "db-1",
				Name: "Database 1",
				Type: "database",
				URN:  "database:db-1",
				Details: map[string]interface{}{
					"id": "db-1",
				},
				Children: []*domain.Resource{},
			},
		},
		{
			name: "resource with empty details",
			resource: Resource{
				ID:   "empty-1",
				Name: "Empty Resource",
				Type: "empty",
				Details: map[string]interface{}{
					"id": "empty-1",
				},
			},
			expected: &domain.Resource{
				ID:   "empty-1",
				Name: "Empty Resource",
				Type: "empty",
				URN:  "empty:empty-1",
				Details: map[string]interface{}{
					"id": "empty-1",
				},
				Children: []*domain.Resource{},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.resource.ToDomain()
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestResource_String(t *testing.T) {
	tests := []struct {
		name     string
		resource Resource
		expected string
	}{
		{
			name: "resource with all fields",
			resource: Resource{
				ID:   "proj-1",
				Name: "Project 1",
				Type: "project",
				Details: map[string]interface{}{
					"status": "active",
				},
			},
			expected: "Resource{ID: proj-1, Name: Project 1, Type: project}",
		},
		{
			name: "resource with empty name",
			resource: Resource{
				ID:   "test-id",
				Name: "",
				Type: "test",
				Details: map[string]interface{}{
					"data": "value",
				},
			},
			expected: "Resource{ID: test-id, Name: , Type: test}",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.resource.String()
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestCreateResource(t *testing.T) {
	tests := []struct {
		testName string
		id       string
		name     string
		resType  string
		details  map[string]interface{}
		expected Resource
	}{
		{
			testName: "create resource with all fields",
			id:       "res-1",
			name:     "Resource 1",
			resType:  "database",
			details: map[string]interface{}{
				"host": "localhost",
				"port": 5432,
			},
			expected: Resource{
				ID:   "res-1",
				Name: "Resource 1",
				Type: "database",
				Details: map[string]interface{}{
					"host": "localhost",
					"port": 5432,
				},
			},
		},
		{
			testName: "create resource with minimal fields",
			id:       "minimal",
			name:     "Minimal",
			resType:  "basic",
			details:  nil,
			expected: Resource{
				ID:      "minimal",
				Name:    "Minimal",
				Type:    "basic",
				Details: nil,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.testName, func(t *testing.T) {
			result := Resource{
				ID:      tt.id,
				Name:    tt.name,
				Type:    tt.resType,
				Details: tt.details,
			}
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestResourceSliceConversion(t *testing.T) {
	tests := []struct {
		name      string
		resources []Resource
		expected  []*domain.Resource
	}{
		{
			name: "convert multiple resources",
			resources: []Resource{
				{
					ID:      "proj-1",
					Name:    "Project 1",
					Type:    "project",
					Details: map[string]interface{}{"id": "proj-1"},
				},
				{
					ID:      "proj-2",
					Name:    "Project 2",
					Type:    "project",
					Details: map[string]interface{}{"id": "proj-2"},
				},
			},
			expected: []*domain.Resource{
				{
					ID:       "proj-1",
					Name:     "Project 1",
					Type:     "project",
					URN:      "project:proj-1",
					Details:  map[string]interface{}{"id": "proj-1"},
					Children: []*domain.Resource{},
				},
				{
					ID:       "proj-2",
					Name:     "Project 2",
					Type:     "project",
					URN:      "project:proj-2",
					Details:  map[string]interface{}{"id": "proj-2"},
					Children: []*domain.Resource{},
				},
			},
		},
		{
			name:      "convert empty slice",
			resources: []Resource{},
			expected:  []*domain.Resource{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := make([]*domain.Resource, 0, len(tt.resources))
			for _, res := range tt.resources {
				result = append(result, res.ToDomain())
			}
			assert.Equal(t, tt.expected, result)
		})
	}
}
