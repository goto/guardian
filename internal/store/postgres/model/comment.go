package model

import (
	"time"

	"github.com/google/uuid"
	"github.com/goto/guardian/domain"
	"gorm.io/gorm"
)

type Comment struct {
	ID         uuid.UUID `gorm:"type:uuid;primaryKey;default:uuid_generate_v4()"`
	ParentType string
	ParentID   string
	CreatedBy  string
	Body       string
	CreatedAt  time.Time      `gorm:"autoCreateTime"`
	UpdatedAt  time.Time      `gorm:"autoUpdateTime"`
	DeletedAt  gorm.DeletedAt `gorm:"index"`
}

func (Comment) TableName() string {
	return "comments"
}

func (m *Comment) FromDomain(c *domain.Comment) error {
	if c.ID != "" {
		if uuid, err := uuid.Parse(c.ID); err != nil {
			return err
		} else {
			m.ID = uuid
		}
	}

	m.ParentType = c.ParentType
	m.ParentID = c.ParentID
	m.CreatedBy = c.CreatedBy
	m.Body = c.Body
	m.CreatedAt = c.CreatedAt
	m.UpdatedAt = c.UpdatedAt

	return nil
}

func (m *Comment) ToDomain() *domain.Comment {
	return &domain.Comment{
		ID:         m.ID.String(),
		ParentType: m.ParentType,
		ParentID:   m.ParentID,
		CreatedBy:  m.CreatedBy,
		Body:       m.Body,
		CreatedAt:  m.CreatedAt,
		UpdatedAt:  m.UpdatedAt,
	}
}
