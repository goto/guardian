package domain

type NotificationMessages struct {
	ExpirationReminder       string `mapstructure:"expiration_reminder"`
	AppealApproved           string `mapstructure:"appeal_approved"`
	AppealRejected           string `mapstructure:"appeal_rejected"`
	AccessRevoked            string `mapstructure:"access_revoked"`
	ApproverNotification     string `mapstructure:"approver_notification"`
	OthersAppealApproved     string `mapstructure:"others_appeal_approved"`
	GrantOwnerChanged        string `mapstructure:"grant_owner_changed"`
	UnusedGrant              string `mapstructure:"unused_grant"`
	NewComment               string `mapstructure:"new_comment"`
	PendingApprovalsReminder string `mapstructure:"pending_approvals_reminder"`
}

const (
	NotificationTypeExpirationReminder       = "ExpirationReminder"
	NotificationTypeAppealApproved           = "AppealApproved"
	NotificationTypeOnBehalfAppealApproved   = "OnBehalfAppealApproved"
	NotificationTypeAppealRejected           = "AppealRejected"
	NotificationTypeAccessRevoked            = "AccessRevoked"
	NotificationTypeApproverNotification     = "ApproverNotification"
	NotificationTypeGrantOwnerChanged        = "GrantOwnerChanged"
	NotificationTypeUnusedGrant              = "UnusedGrant"
	NotificationTypeNewComment               = "NewComment"
	NotificationTypePendingApprovalsReminder = "PendingApprovalsReminder"
)

type NotificationMessage struct {
	Type      string
	Variables map[string]interface{}
}

// NotificationApproval binds an interactive notification to persisted approval steps.
// It is transport metadata and is not persisted in Guardian's database.
type NotificationApproval struct {
	AppealID   string                     `json:"appeal_id"`
	ApprovalID string                     `json:"approval_id,omitempty"`
	Revision   uint32                     `json:"revision"`
	Steps      []NotificationApprovalStep `json:"steps,omitempty"`
}

type NotificationApprovalStep struct {
	ApprovalID string `json:"approval_id"`
	Name       string `json:"name"`
}

type Notification struct {
	User    string
	Message NotificationMessage

	Labels   map[string]string
	Approval *NotificationApproval `json:"approval,omitempty"`
}
