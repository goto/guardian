package alicloudiam

import (
	"errors"
	"fmt"
)

var (
	ErrUnableToEncryptNilCredentials = errors.New("unable to encrypt nil credentials")
	ErrUnableToDecryptNilCredentials = errors.New("unable to decrypt nil credentials")
	ErrInvalidCredentials            = errors.New("invalid credentials type")
	ErrPermissionAlreadyExists       = errors.New("permission already exists")
	ErrPermissionNotExist            = errors.New("permission not exist")
	ErrInvalidResourceType           = errors.New("invalid resource type")
	ErrInvalidAccountType            = fmt.Errorf("invalid account type. account type must be one of: %v\n", getAccountTypes())
	ErrRolesShouldNotBeEmpty         = errors.New("alicloud_iam provider should not have empty roles")
	ErrInvalidRoleType               = errors.New("invalid role type. it seems the provider configuration is malformed at 'resources[i].roles[i].type'. default: System. see: https://www.alibabacloud.com/help/en/ram/developer-reference/api-ram-2015-05-01-getpolicy at request parameters field 'PolicyType' for kind of role types")
	ErrInvalidAliAccountUserID       = errors.New("invalid ali account user id. see: https://github.com/goto/guardian/tree/main/plugins/providers/alicloudiam/docs/ali-account-user-id-example.png")
)
