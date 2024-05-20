package domain

import (
	"fmt"
	"strings"
	"time"

	"github.com/goto/salt/audit"
)

type Event struct {
	ParentType string         `json:"parent_type"`
	ParentID   string         `json:"parent_id"`
	Timestamp  time.Time      `json:"timestamp"`
	Type       string         `json:"type"`
	Actor      string         `json:"actor"`
	Data       map[string]any `json:"data"`
}

func (e *Event) FromAuditLog(l *audit.Log) error {
	var parentType string
	parentType = strings.Split(l.Action, ".")[0]
	switch parentType {
	case "appeal":
		data, ok := l.Data.(map[string]any)
		if !ok {
			return fmt.Errorf("invalid data type %T", l.Data)
		}
		e.Data = data

		id, ok := data["appeal_id"].(string)
		if !ok {
			return fmt.Errorf("invalid parent_id=%q for parent_type=%q", id, parentType)
		}
		e.ParentID = id
	default:
		return fmt.Errorf("invalid parent type %q", parentType)
	}

	e.Timestamp = l.Timestamp
	e.Type = l.Action
	e.Actor = l.Actor
	e.ParentType = parentType
	return nil
}

type ListEventsFilter struct {
	Types      []string
	ParentType string
	ParentID   string
}
