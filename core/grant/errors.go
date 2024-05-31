package grant

import "errors"

var (
	ErrEmptyIDParam        = errors.New("grant id can't be empty")
	ErrInvalidRequest      = errors.New("invalid request")
	ErrGrantNotFound       = errors.New("grant not found")
	ErrEmptyImportedGrants = errors.New("imported grants not found")
	ErrEmptyOwner          = errors.New("owner can't be empty")
)
