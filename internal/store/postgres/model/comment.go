package model

import (
	"time"

	"github.com/google/uuid"
	"github.com/goto/guardian/domain"
	"gorm.io/gorm"
)

type Comment struct {
	ID        uuid.UUID `gorm:"type:uuid;primaryKey;default:uuid_generate_v4()"`
	AppealID  uuid.UUID `gorm:"type:uuid"`
	CreatedBy string
	Body      string
	CreatedAt time.Time      `gorm:"autoCreateTime"`
	UpdatedAt time.Time      `gorm:"autoUpdateTime"`
	DeletedAt gorm.DeletedAt `gorm:"index"`
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

	if c.AppealID != "" {
		if uuid, err := uuid.Parse(c.AppealID); err != nil {
			return err
		} else {
			m.AppealID = uuid
		}
	}

	m.CreatedBy = c.CreatedBy
	m.Body = c.Body
	m.CreatedAt = c.CreatedAt
	m.UpdatedAt = c.UpdatedAt

	return nil
}

func (m *Comment) ToDomain() *domain.Comment {
	return &domain.Comment{
		ID:        m.ID.String(),
		AppealID:  m.AppealID.String(),
		CreatedBy: m.CreatedBy,
		Body:      m.Body,
		CreatedAt: m.CreatedAt,
		UpdatedAt: m.UpdatedAt,
	}
}
