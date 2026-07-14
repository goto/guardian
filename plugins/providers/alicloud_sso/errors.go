package alicloud_sso

import (
	"errors"
	"net/http"
	"strings"

	"github.com/alibabacloud-go/tea/tea"
)

// isPolicyAlreadyExistsErr reports whether err indicates that the permission
// policy is already attached to the access configuration. Such errors are
// treated as success to keep GrantAccess idempotent.
func isPolicyAlreadyExistsErr(err error) bool {
	if err == nil {
		return false
	}
	var sdkErr *tea.SDKError
	if errors.As(err, &sdkErr) {
		if sdkErr.StatusCode != nil && *sdkErr.StatusCode == http.StatusConflict {
			return true
		}
		if sdkErr.Code != nil && strings.Contains(strings.ToLower(*sdkErr.Code), "alreadyexists") {
			return true
		}
	}
	return strings.Contains(strings.ToLower(err.Error()), "alreadyexists")
}

// isPolicyNotExistsErr reports whether err indicates that the permission policy
// is not attached to the access configuration. Such errors are treated as
// success to keep RevokeAccess idempotent.
func isPolicyNotExistsErr(err error) bool {
	if err == nil {
		return false
	}
	var sdkErr *tea.SDKError
	if errors.As(err, &sdkErr) && sdkErr.Code != nil && strings.Contains(strings.ToLower(*sdkErr.Code), "notexist") {
		return true
	}
	return strings.Contains(strings.ToLower(err.Error()), "notexist")
}
