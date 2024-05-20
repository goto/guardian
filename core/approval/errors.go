package approval

import "errors"

var (
	ErrAppealIDEmptyParam   = errors.New("appeal id is required")
	ErrApprovalIDEmptyParam = errors.New("approval id is required")
	ErrApprovalNotFound     = errors.New("approval not found")
)
