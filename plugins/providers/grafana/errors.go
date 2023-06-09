package grafana

import "errors"

var (
	ErrInvalidRole             = errors.New("invalid role")
	ErrInvalidPermissionType   = errors.New("invalid permission type")
	ErrUserNotFound            = errors.New("cannot find user with the given email")
	ErrPermissionNotFound      = errors.New("permission not found")
	ErrInvalidResourceType     = errors.New("invalid resource type")
	ErrInvalidCredentials      = errors.New("invalid credentials type")
	ErrInvalidPermissionConfig = errors.New("invalid permission config type")
)
