package googlegroup

import "errors"

const (
	// account types
	accountTypeUser           = "user"
	accountTypeGroup          = "google-group"
	accountTypeServiceAccount = "service-account"

	// resource types
	resourceTypeGroup = "group"

	// roles
	roleMember  = "member"
	roleManager = "manager"
	roleOwner   = "owner"

	emailRegexPattern = `^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$`
	saRegexPattern    = `^.+@.+\.iam\.gserviceaccount\.com$`
)

// errors
var (
	ErrInvalidResourceType              = errors.New("invalid resource type")
	ErrMissingServiceAccountKey         = errors.New("service_account_key is required")
	ErrMissingImpersonateUserEmail      = errors.New("impersonate_user_email is required")
	ErrInvalidBase64                    = errors.New("service_account_key must be a valid base64 encoded string")
	ErrInvalidEmailFormat               = errors.New("impersonate_user_email must be a valid email address")
	ErrUnableToEncryptNilCredentials    = errors.New("unable to encrypt nil credentials")
	ErrUnableToDecryptNilCredentials    = errors.New("unable to decrypt nil credentials")
	ErrCredentialsNotFound              = errors.New("credentials not found in provider config")
	ErrInvalidUserEmailFormat           = errors.New("invalid email format for user account type")
	ErrInvalidServiceAccountEmailFormat = errors.New("invalid email format for service account, must end with .iam.gserviceaccount.com")
)
