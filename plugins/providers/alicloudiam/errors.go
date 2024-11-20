package alicloudiam

import (
	"errors"
	"fmt"
)

var (
	ErrUnimplementedMethod           = errors.New("unimplemented method")
	ErrUnableToEncryptNilCredentials = errors.New("unable to encrypt nil credentials")
	ErrUnableToDecryptNilCredentials = errors.New("unable to decrypt nil credentials")
	ErrInvalidCredentials            = errors.New("invalid credentials type")
	ErrPermissionAlreadyExists       = errors.New("permission already exists")
	ErrPermissionNotExist            = errors.New("permission not exist")
	ErrInvalidResourceType           = errors.New("invalid resource type")
	ErrInvalidAccountType            = fmt.Errorf("invalid account type. account type must be one of: %v\n", getAccountTypes())
	ErrGrantRoleNotFoundAtResource   = errors.New("grant role not found at resource")
	ErrEmptyGrantRole                = errors.New("empty grant role")
	ErrInvalidPolicyType             = fmt.Errorf("invalid policy type. policy type must be one of: %v\n", getPolicyTypes())
	ErrInvalidAliAccountUserID       = errors.New("invalid ali account user id. see: https://github.com/goto/guardian/tree/main/plugins/providers/alicloudiam/docs/ali-account-user-id-example.png")
	ErrEmptyResourceConfig           = errors.New("empty resource config")
)
