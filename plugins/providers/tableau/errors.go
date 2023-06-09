package tableau

import "errors"

var (
	ErrInvalidRole             = errors.New("invalid role")
	ErrInvalidResourceType     = errors.New("invalid resource type")
	ErrUserNotFound            = errors.New("cannot find user with the given email")
	ErrInvalidCredentials      = errors.New("invalid credentials type")
	ErrInvalidPermissionConfig = errors.New("invalid permission config type")
)
