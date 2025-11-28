package model

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"
	"gorm.io/datatypes"
	"gorm.io/gorm"

	"github.com/goto/guardian/domain"
)

// Approval database model
type Approval struct {
	ID            uuid.UUID `gorm:"type:uuid;primaryKey;default:uuid_generate_v4()"`
	Name          string    `gorm:"index"`
	Index         int
	AppealID      string
	Status        string
	Actor         *string
	Reason        string
	PolicyID      string
	PolicyVersion uint

	AllowFailed           bool
	DontAllowSelfApproval bool
	Details               datatypes.JSON

	Approvers []Approver
	Appeal    *Appeal

	IsStale        bool
	AppealRevision uint

	CreatedAt time.Time      `gorm:"autoCreateTime"`
	UpdatedAt time.Time      `gorm:"autoUpdateTime"`
	DeletedAt gorm.DeletedAt `gorm:"index"`
}

// FromDomain transforms *domain.Approval values into the model
func (m *Approval) FromDomain(a *domain.Approval) error {
	details, err := json.Marshal(a.Details)
	if err != nil {
		return err
	}

	var approvers []Approver
	if a.Approvers != nil {
		for _, approver := range a.Approvers {
			m := new(Approver)
			if err := m.FromDomain(&domain.Approver{Email: approver}); err != nil {
				return err
			}
			approvers = append(approvers, *m)
		}
	}

	if a.Appeal != nil {
		appealModel := new(Appeal)
		if err := appealModel.FromDomain(a.Appeal); err != nil {
			return err
		}
		m.Appeal = appealModel
	}

	var id uuid.UUID
	if a.ID != "" {
		uuid, err := uuid.Parse(a.ID)
		if err != nil {
			return fmt.Errorf("parsing uuid: %w", err)
		}
		id = uuid
	}

	m.ID = id
	m.Name = a.Name
	m.Index = a.Index
	m.AppealID = a.AppealID
	m.Status = a.Status
	m.Actor = a.Actor
	m.Reason = a.Reason
	m.PolicyID = a.PolicyID
	m.PolicyVersion = a.PolicyVersion
	m.AllowFailed = a.AllowFailed
	m.DontAllowSelfApproval = a.DontAllowSelfApproval
	m.Details = details
	m.Approvers = approvers
	m.IsStale = a.IsStale
	m.AppealRevision = a.AppealRevision
	m.CreatedAt = a.CreatedAt
	m.UpdatedAt = a.UpdatedAt

	return nil
}

// ToDomain transforms model into *domain.Approval
func (m *Approval) ToDomain() (*domain.Approval, error) {
	var details map[string]interface{}
	if m.Details != nil {
		if err := json.Unmarshal(m.Details, &details); err != nil {
			return nil, err
		}
	}

	var approvers []string
	if m.Approvers != nil {
		for _, a := range m.Approvers {
			approver := a.ToDomain()
			approvers = append(approvers, approver.Email)
		}
	}

	var appeal *domain.Appeal
	if m.Appeal != nil {
		a, err := m.Appeal.ToDomain()
		if err != nil {
			return nil, err
		}
		appeal = a
	}

	return &domain.Approval{
		ID:                    m.ID.String(),
		Name:                  m.Name,
		Index:                 m.Index,
		AppealID:              m.AppealID,
		Status:                m.Status,
		Actor:                 m.Actor,
		Reason:                m.Reason,
		PolicyID:              m.PolicyID,
		PolicyVersion:         m.PolicyVersion,
		AllowFailed:           m.AllowFailed,
		DontAllowSelfApproval: m.DontAllowSelfApproval,
		Details:               details,
		Approvers:             approvers,
		Appeal:                appeal,
		IsStale:               m.IsStale,
		AppealRevision:        m.AppealRevision,
		CreatedAt:             m.CreatedAt,
		UpdatedAt:             m.UpdatedAt,
	}, nil
}
