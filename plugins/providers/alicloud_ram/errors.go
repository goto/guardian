package alicloud_ram

import (
	"errors"
	"fmt"
)

var (
	ErrUnimplementedMethod            = errors.New("unimplemented method")
	ErrUnableToEncryptNilCredentials  = errors.New("unable to encrypt nil credentials")
	ErrUnableToDecryptNilCredentials  = errors.New("unable to decrypt nil credentials")
	ErrInvalidCredentials             = errors.New("invalid credentials type")
	ErrPermissionAlreadyExists        = errors.New("permission already exists")
	ErrPermissionNotExist             = errors.New("permission not exist")
	ErrInvalidResourceType            = errors.New("invalid resource type")
	ErrInvalidAccountType             = fmt.Errorf("invalid account type. account type must be one of: %v\n", getAccountTypes())
	ErrInvalidAliCloudAccountUserID   = errors.New("invalid account_id for ali account user id. see: https://github.com/goto/guardian/tree/main/plugins/providers/alicloud_ram/docs/ali-account-user-id-example.png")
	ErrInvalidAliCloudRoleARN         = errors.New("invalid ram_role arn. see: https://github.com/goto/guardian/tree/main/plugins/providers/alicloud_ram/docs/ali-role-arn-example.png")
	ErrRoleServiceTypeIsNotSupported  = errors.New("ram_role arn only supporting service type 'ram'. see: https://github.com/goto/guardian/tree/main/plugins/providers/alicloud_ram/docs/ali-role-arn-structure.png")
	ErrRoleResourceTypeIsNotSupported = errors.New("ram_role arn only supporting resource type 'role'. see: https://github.com/goto/guardian/tree/main/plugins/providers/alicloud_ram/docs/ali-role-arn-structure.png")
	ErrRoleResourceNameIsEmpty        = errors.New("empty resource name / role name on the ram_role arn. see: https://github.com/goto/guardian/tree/main/plugins/providers/alicloud_ram/docs/ali-role-arn-structure.png")
	ErrEmptyResourceConfig            = errors.New("empty resource config")
)
