package alicloud_ram

import "sync"

type Principal struct {
	RAM []string `json:"RAM"`
}
type Statement struct {
	Action    string    `json:"Action"`
	Effect    string    `json:"Effect"`
	Principal Principal `json:"Principal"`
}
type RAMPolicy struct {
	Statement []Statement `json:"Statement"`
	Version   string      `json:"Version"`
}

type aliCloudRAMClient struct {
	accessKeyId     string
	accessKeySecret string
	ramRole         string
	regionId        string

	// per-role mutex to prevent race conditions on GetRole + UpdateRole
	roleMu sync.Map // map[string]*sync.Mutex
}

type Role struct {
	Arn                      *string `json:"Arn,omitempty"`
	AssumeRolePolicyDocument *string `json:"AssumeRolePolicyDocument,omitempty"`
	CreateDate               *string `json:"CreateDate,omitempty"`
	Description              *string `json:"Description,omitempty"`
	MaxSessionDuration       *int64  `json:"MaxSessionDuration,omitempty"`
	RoleID                   *string `json:"RoleId,omitempty"`
	RoleName                 *string `json:"RoleName,omitempty"`
}
