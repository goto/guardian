package domain

import (
	"context"
	"time"
)

// User represents a user record in Shield
type User struct {
	ID        string                 `json:"id"`
	Name      string                 `json:"name"`
	Email     string                 `json:"email"`
	Metadata  map[string]interface{} `json:"metadata"`
	CreatedAt time.Time              `json:"createdAt"`
	UpdatedAt time.Time              `json:"updatedAt"`
}

type GetUserResponse struct {
	User User `json:"user"`
}

// Group represents a single team/group in Shield
type Group struct {
	ID       string                 `json:"id"`
	Name     string                 `json:"name"`
	Slug     string                 `json:"slug"`
	OrgID    string                 `json:"orgId"`
	Metadata map[string]interface{} `json:"metadata"`
}

type GetUserGroupsResponse struct {
	Groups []Group `json:"groups"`
}

type UserManagement interface {
	GetUser(ctx context.Context, email string) (*User, error)
	GetUserGroups(ctx context.Context, userID string) ([]Group, error)
}
