package report

type Report struct {
	ID        string `json:"id" yaml:"id"` //appeal_id
	Approver  string `json:"approver" yaml:"approver"`
	Requestor string `json:"requestor" yaml:"requestor"`
	Project   string `json:"project" yaml:"project"`
	Resource  string `json:"resource" yaml:"resource"`
	Status    string `json:"status" yaml:"status"`
	CreatedAt string `json:"created_at" yaml:"created_at"`
}

type ReportFilter struct {
	Q                string   `mapstructure:"q" validate:"omitempty"`
	AccountID        string   `mapstructure:"account_id" validate:"omitempty,required"`
	AccountTypes     []string `mapstructure:"account_types" validate:"omitempty,min=1"`
	ResourceTypes    []string `mapstructure:"resource_types" validate:"omitempty,min=1"`
	CreatedBy        string   `mapstructure:"created_by" validate:"omitempty,required"`
	OrderBy          []string `mapstructure:"order_by" validate:"omitempty,min=1"`
	Size             int      `mapstructure:"size" validate:"omitempty"`
	Offset           int      `mapstructure:"offset" validate:"omitempty"`
	AppealStatuses   []string `mapstructure:"appeal_statuses" validate:"omitempty,min=1"`
	ApprovalStatuses []string `mapstructure:"approval_statuses" validate:"omitempty,min=1"`
	Stale            bool     `mapstructure:"stale" validate:"omitempty"`
}
