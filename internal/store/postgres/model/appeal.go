package model

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/goto/guardian/domain"
	"github.com/lib/pq"
	"gorm.io/datatypes"
	"gorm.io/gorm"
)

// Appeal database model
type Appeal struct {
	ID             uuid.UUID `gorm:"type:uuid;primaryKey;default:uuid_generate_v4()"`
	ResourceID     string
	PolicyID       string
	PolicyVersion  uint
	Status         string
	AccountID      string
	AccountType    string
	GroupID        sql.NullString
	GroupType      sql.NullString
	CreatedBy      string
	Creator        datatypes.JSON
	Role           string
	Permissions    pq.StringArray `gorm:"type:text[]"`
	Options        datatypes.JSON
	Labels         datatypes.JSON
	LabelsMetadata datatypes.JSON
	Details        datatypes.JSON
	Description    string

	Resource  *Resource `gorm:"ForeignKey:ResourceID;References:ID"`
	Policy    Policy    `gorm:"ForeignKey:PolicyID,PolicyVersion;References:ID,Version"`
	Approvals []*Approval
	Grant     *Grant

	Revision uint

	CreatedAt time.Time      `gorm:"autoCreateTime"`
	UpdatedAt time.Time      `gorm:"autoUpdateTime"`
	DeletedAt gorm.DeletedAt `gorm:"index"`
}

// FromDomain transforms *domain.Appeal values into the model
func (m *Appeal) FromDomain(a *domain.Appeal) error {
	labels, err := json.Marshal(a.Labels)
	if err != nil {
		return err
	}

	labelsMetadata, err := json.Marshal(a.LabelsMetadata)
	if err != nil {
		return err
	}

	options, err := json.Marshal(a.Options)
	if err != nil {
		return err
	}

	details, err := json.Marshal(a.Details)
	if err != nil {
		return err
	}

	creator, err := json.Marshal(a.Creator)
	if err != nil {
		return err
	}

	var approvals []*Approval
	if a.Approvals != nil {
		for _, approval := range a.Approvals {
			m := new(Approval)
			if err := m.FromDomain(approval); err != nil {
				return err
			}
			approvals = append(approvals, m)
		}
	}

	if a.Resource != nil {
		r := new(Resource)
		if err := r.FromDomain(a.Resource); err != nil {
			return err
		}
		m.Resource = r
	}

	if a.Grant != nil {
		grant := new(Grant)
		if err := grant.FromDomain(*a.Grant); err != nil {
			return fmt.Errorf("parsing grant: %w", err)
		}
		m.Grant = grant
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
	m.ResourceID = a.ResourceID
	m.PolicyID = a.PolicyID
	m.PolicyVersion = a.PolicyVersion
	m.Status = a.Status
	m.AccountID = a.AccountID
	m.AccountType = a.AccountType
	m.GroupID = sql.NullString{
		String: a.GroupID,
		Valid:  a.GroupID != "",
	}
	m.GroupType = sql.NullString{
		String: a.GroupType,
		Valid:  a.GroupType != "",
	}
	m.CreatedBy = a.CreatedBy
	m.Creator = datatypes.JSON(creator)
	m.Role = a.Role
	m.Permissions = pq.StringArray(a.Permissions)
	m.Options = datatypes.JSON(options)
	m.Labels = datatypes.JSON(labels)
	m.LabelsMetadata = datatypes.JSON(labelsMetadata)
	m.Details = datatypes.JSON(details)
	m.Description = a.Description
	m.Approvals = approvals
	m.Revision = a.Revision
	m.CreatedAt = a.CreatedAt
	m.UpdatedAt = a.UpdatedAt

	return nil
}

// ToDomain transforms model into *domain.Appeal
func (m *Appeal) ToDomain() (*domain.Appeal, error) {
	var labels map[string]string
	if err := json.Unmarshal(m.Labels, &labels); err != nil {
		return nil, err
	}

	var labelsMetadata map[string]*domain.LabelMetadata
	if m.LabelsMetadata != nil {
		if err := json.Unmarshal(m.LabelsMetadata, &labelsMetadata); err != nil {
			return nil, err
		}
	}

	var options *domain.AppealOptions
	if m.Options != nil {
		if err := json.Unmarshal(m.Options, &options); err != nil {
			return nil, err
		}
	}

	var details map[string]interface{}
	if m.Details != nil {
		if err := json.Unmarshal(m.Details, &details); err != nil {
			return nil, err
		}
	}

	var creator interface{}
	if m.Creator != nil {
		if err := json.Unmarshal(m.Creator, &creator); err != nil {
			return nil, err
		}
	}

	var approvals []*domain.Approval
	if m.Approvals != nil {
		for _, a := range m.Approvals {
			if a != nil {
				approval, err := a.ToDomain()
				if err != nil {
					return nil, err
				}
				approvals = append(approvals, approval)
			}
		}
	}

	var resource *domain.Resource
	if m.Resource != nil {
		r, err := m.Resource.ToDomain()
		if err != nil {
			return nil, err
		}
		resource = r
	}

	var grant *domain.Grant
	if m.Grant != nil {
		a, err := m.Grant.ToDomain()
		if err != nil {
			return nil, fmt.Errorf("parsing grant: %w", err)
		}
		grant = a
	}
	groupID := ""
	if m.GroupID.Valid {
		groupID = m.GroupID.String
	}
	groupType := ""
	if m.GroupType.Valid {
		groupType = m.GroupType.String
	}

	return &domain.Appeal{
		ID:             m.ID.String(),
		ResourceID:     m.ResourceID,
		PolicyID:       m.PolicyID,
		PolicyVersion:  m.PolicyVersion,
		Status:         m.Status,
		AccountID:      m.AccountID,
		AccountType:    m.AccountType,
		GroupID:        groupID,
		GroupType:      groupType,
		CreatedBy:      m.CreatedBy,
		Creator:        creator,
		Role:           m.Role,
		Permissions:    []string(m.Permissions),
		Options:        options,
		Details:        details,
		Description:    m.Description,
		Labels:         labels,
		LabelsMetadata: labelsMetadata,
		Approvals:      approvals,
		Resource:       resource,
		Revision:       m.Revision,
		Grant:          grant,
		CreatedAt:      m.CreatedAt,
		UpdatedAt:      m.UpdatedAt,
	}, nil
}
