package alicatalogapis

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"

	"github.com/bearaujus/berror"
)

var (
	ErrInitMissingAccessKeyID     = errors.New("access key id is missing")
	ErrInitMissingAccessKeySecret = errors.New("access key secret is missing")
	ErrInitMissingAccountID       = errors.New("account id is missing")
	ErrInitMissingRegionID        = errors.New("region id is missing")
)

var (
	ErrRoleBindingProjectBadRequest = berror.NewErrDefinition("bad request. err: %v",
		newErrOptions("role_binding_project", "001")...)
	ErrRoleBindingProjectFailMarshalJSON = berror.NewErrDefinition("fail to marshal json. data: %v. err: %v",
		newErrOptions("role_binding_project", "002")...)
	ErrRoleBindingProjectRoleNotExist = berror.NewErrDefinition("role '%v' does not exist. err: %v",
		newErrOptions("role_binding_project", "003")...)
	ErrRoleBindingProjectEmptyMemberToBind = berror.NewErrDefinition("empty member to bind into role '%v'",
		newErrOptions("role_binding_project", "004")...)
	ErrRoleBindingProjectMissingProject = berror.NewErrDefinition("project is missing",
		newErrOptions("role_binding_project", "005")...)
	ErrRoleBindingProjectMissingRole = berror.NewErrDefinition("role is missing",
		newErrOptions("role_binding_schema", "006")...)
)

var (
	ErrRoleBindingSchemaBadRequest = berror.NewErrDefinition("bad request. err: %v",
		newErrOptions("role_binding_schema", "001")...)
	ErrRoleBindingSchemaFailMarshalJSON = berror.NewErrDefinition("fail to marshal json. data: %v. err: %v",
		newErrOptions("role_binding_schema", "002")...)
	ErrRoleBindingSchemaRoleNotExist = berror.NewErrDefinition("role '%v' does not exist. err: %v",
		newErrOptions("role_binding_schema", "003")...)
	ErrRoleBindingSchemaEmptyMemberToBind = berror.NewErrDefinition("empty member to bind into role '%v'",
		newErrOptions("role_binding_schema", "004")...)
	ErrRoleBindingSchemaEmptyMemberToUnbind = berror.NewErrDefinition("empty member to unbind into role '%v'",
		newErrOptions("role_binding_schema", "005")...)
	ErrRoleBindingSchemaMissingProject = berror.NewErrDefinition("project is missing",
		newErrOptions("role_binding_schema", "006")...)
	ErrRoleBindingSchemaMissingSchema = berror.NewErrDefinition("schema is missing",
		newErrOptions("role_binding_schema", "007")...)
	ErrRoleBindingSchemaMissingRole = berror.NewErrDefinition("role is missing",
		newErrOptions("role_binding_schema", "008")...)
)

func newErrOptions(module string, code string) []berror.ErrDefinitionOption {
	return []berror.ErrDefinitionOption{
		berror.OptionErrDefinitionWithErrCode(fmt.Sprintf("alicatalogapis-%v-%v", module, code)),
		berror.OptionErrDefinitionWithDisabledStackTrace(),
	}
}

func newRespErr(resp *http.Response) *commonRespErr {
	return &commonRespErr{RequestID: resp.Header.Get("x-odps-request-id"), StatusCode: resp.StatusCode}
}

type commonRespErr struct {
	RequestID  string      `json:"x-odps-request-id,omitempty"`
	StatusCode int         `json:"status_code"`
	Reason     string      `json:"reason"`
	Data       interface{} `json:"data,omitempty"`
}

func (e *commonRespErr) FromErr(reason string, err error) error {
	e.Reason = reason
	if err != nil {
		e.Data = err.Error()
	}
	errData, _ := json.MarshalIndent(e, "", "   ")
	return errors.New(string(errData))
}

func (e *commonRespErr) FromResponseBody(reason string, respData []byte) error {
	e.Reason = reason
	if respData == nil || len(respData) == 0 {
		e.Reason += fmt.Sprintf(" (empty response)")
	}
	var errMsg interface{}
	if err := json.Unmarshal(respData, &errMsg); err == nil {
		e.Data = errMsg
	} else {
		e.Data = string(respData)
	}
	errData, _ := json.MarshalIndent(e, "", "   ")
	return errors.New(string(errData))
}
