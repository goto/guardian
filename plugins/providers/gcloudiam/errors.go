package gcloudiam

import "errors"

var (
	ErrInvalidPermissionConfig = errors.New("invalid permission config type")
	ErrInvalidCredentials      = errors.New("invalid credentials type")
	ErrPermissionAlreadyExists = errors.New("permission already exists")
	ErrPermissionNotFound      = errors.New("permission not found")
	ErrInvalidResourceType     = errors.New("invalid resource type")
	ErrInvalidRole             = errors.New("invalid role")
	ErrShouldHaveOneResource   = errors.New("gcloud_iam should have one resource")
	ErrInvalidResourceName     = errors.New("invalid resource name: resource name should be projects/{{project-id}} or organizations/{{org-id}}")
	ErrRolesShouldNotBeEmpty   = errors.New("gcloud_iam provider should not have empty roles")
	ErrInvalidProjectRole      = errors.New("provided role is not supported for project in gcloud")
)
