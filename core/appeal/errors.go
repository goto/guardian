package appeal

import (
	"errors"
	"fmt"
	"time"
)

var (
	ErrAppealIDEmptyParam   = errors.New("appeal id is required")
	ErrApprovalIDEmptyParam = errors.New("approval id/name is required")

	ErrAppealStatusCanceled           = errors.New("appeal already canceled")
	ErrAppealStatusApproved           = errors.New("appeal already approved")
	ErrAppealStatusRejected           = errors.New("appeal already rejected")
	ErrAppealStatusUnrecognized       = errors.New("unrecognized appeal status")
	ErrAppealDuplicate                = errors.New("appeal with identical account_id, resource, and role already exists")
	ErrAppealInvalidExtensionDuration = errors.New("invalid configured appeal extension duration")
	ErrAppealFoundActiveGrant         = errors.New("user still have an active grant")
	ErrGrantNotEligibleForExtension   = errors.New("grant not eligible for extension")
	ErrCannotCreateAppealForOtherUser = errors.New("creating appeal for other individual user (account_type=\"user\") is not allowed")

	ErrApprovalStatusUnrecognized = errors.New("unrecognized approval status")
	ErrApprovalNotFound           = errors.New("approval not found")
	ErrUnableToAddApprover        = errors.New("unable to add a new approver")
	ErrUnableToDeleteApprover     = errors.New("unable to remove approver")

	ErrActionForbidden    = errors.New("user is not allowed to make action on this approval step")
	ErrActionInvalidValue = errors.New("invalid action value")

	ErrProviderNotFound                    = errors.New("provider not found")
	ErrInvalidResourceType                 = errors.New("invalid resource type")
	ErrOptionsExpirationDateOptionNotFound = errors.New("expiration date is required, unable to find expiration date option")
	ErrInvalidRole                         = errors.New("invalid role")
	ErrExpirationDateIsRequired            = errors.New("having permanent access to this resource is not allowed, access duration is required")
	ErrPolicyNotFound                      = errors.New("policy not found")
	ErrResourceNotFound                    = errors.New("resource not found")
	ErrResourceDeleted                     = errors.New("resource has been deleted")
	ErrAppealNotFound                      = errors.New("appeal not found")
	ErrDurationNotAllowed                  = errors.New("duration value not allowed")
	ErrDurationIsRequired                  = errors.New("having permanent access to this resource is not allowed, access duration is required")

	ErrApproverKeyNotRecognized       = errors.New("unrecognized approvers key")
	ErrApproverInvalidType            = errors.New("invalid approver type, expected an email string or array of email string")
	ErrApproverEmail                  = errors.New("approver is not a valid email")
	ErrApproverNotFound               = errors.New("approver not found")
	ErrGrantNotFound                  = errors.New("grant not found")
	ErrInvalidUpdateApprovalParameter = errors.New("invalid parameter")

	ErrAppealNotEligibleForApproval = errors.New("appeal status not eligible for approval")
	ErrApprovalNotEligibleForAction = errors.New("approval not eligible for action")

	ErrApprovalStepNameEmpty      = errors.New("approval step name is required")
	ErrApprovalStepApproversEmpty = errors.New("at least one approver is required for approval step")

	ErrAppealStatusInvalid    = errors.New("invalid appeal status")
	ErrNoChanges              = errors.New("no changes found")
	ErrNoPolicyStepFound      = errors.New("no policy step found")
	ErrSelfApprovalNotAllowed = errors.New("requestor is not allowed to approve their own request")
	ErrAppealHasNoGrant       = errors.New("appeal has no active grant to revoke")
)

// PendingAppealConflict identifies the request that is already awaiting approval.
type PendingAppealConflict struct {
	AppealID string
}

func (e *PendingAppealConflict) Error() string {
	return fmt.Sprintf("%s. appeal id: %q", ErrAppealDuplicate, e.AppealID)
}

func (e *PendingAppealConflict) Unwrap() error { return ErrAppealDuplicate }

// ActiveGrantConflict describes the grant that blocked a new or updated appeal.
type ActiveGrantConflict struct {
	ResourceID        string
	ResourceName      string
	AppealID          string
	ExpiresAt         *time.Time
	IsPermanent       bool
	RenewalWindow     string
	RenewalEligibleAt *time.Time
}

func (e *ActiveGrantConflict) Error() string {
	if e.RenewalWindow != "" {
		return fmt.Sprintf("%s: extension is allowed %q before grant expiration", ErrGrantNotEligibleForExtension, e.RenewalWindow)
	}
	return ErrAppealFoundActiveGrant.Error()
}

func (e *ActiveGrantConflict) Unwrap() error {
	if e.RenewalWindow != "" {
		return ErrGrantNotEligibleForExtension
	}
	return ErrAppealFoundActiveGrant
}

type InvalidError struct {
	AppealID string
}

func (ie InvalidError) Error() string {
	return fmt.Sprintf("invalid appeal id: %s", ie.AppealID)
}
