package alicloudiam

import "errors"

var (
	ErrUnableToEncryptNilCredentials = errors.New("unable to encrypt nil credentials")
	ErrUnableToDecryptNilCredentials = errors.New("unable to decrypt nil credentials")
	ErrInvalidCredentials            = errors.New("invalid credentials type")
	ErrPermissionAlreadyExists       = errors.New("permission already exists")
	ErrPermissionNotExist            = errors.New("permission not exist")
	ErrInvalidResourceType           = errors.New("invalid resource type")
	ErrInvalidAccountType            = errors.New("invalid account type")
	ErrRolesShouldNotBeEmpty         = errors.New("gcloud_iam provider should not have empty roles")
	ErrInvalidAliAccountUserID       = errors.New("invalid ali account user id. see: https://github.com/goto/guardian/tree/main/plugins/providers/alicloudiam/docs/ali-account-user-id-example.png")
)
