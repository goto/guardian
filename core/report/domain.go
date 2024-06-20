package report

type PendingApprovalsReport struct {
	ID        string `json:"id" yaml:"id"` //appeal_id
	Approver  string `json:"approver" yaml:"approver"`
	Requestor string `json:"requestor" yaml:"requestor"`
	Project   string `json:"project" yaml:"project"`
	Resource  string `json:"resource" yaml:"resource"`
	Status    string `json:"status" yaml:"status"`
	CreatedAt string `json:"created_at" yaml:"created_at"`
}

type PendingApprovalsReportFilter struct {
	AppealStatuses   []string `mapstructure:"appeal_statuses" validate:"omitempty,min=1"`
	ApprovalStatuses []string `mapstructure:"approval_statuses" validate:"omitempty,min=1"`
}
