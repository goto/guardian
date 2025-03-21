package alicatalogapis

import (
	"encoding/json"
	"errors"
	"fmt"

	"github.com/bearaujus/berror"
)

var (
	errCommonFormatBadRequest           = "bad request. err: %v"
	errCommonFormatFailMarshalJSON      = "fail to marshal json. data: %v. err: %v"
	errCommonFormatRoleNotExist         = "role '%v' does not exist. err: %v"
	errCommonFormatMissingRole          = "role is missing"
	errCommonFormatEmptyMemberToBind    = "empty member to bind into role '%v'"
	errCommonFormatEmptyMemberToUnbind  = "empty member to unbind into role '%v'"
	errCommonFormatMemberAlreadyExist   = "member is already exist. err: %v"
	errCommonFormatMemberOrRoleNotExist = "member or role does not exist. err: %v"
)

var (
	ErrRoleBadRequest = berror.NewErrDefinition(errCommonFormatBadRequest,
		newErrOptions("role", "001")...)
	ErrRoleFailMarshalJSON = berror.NewErrDefinition(errCommonFormatFailMarshalJSON,
		newErrOptions("role", "002")...)
	ErrRoleAlreadyExist = berror.NewErrDefinition("role '%v' is already exist. err: %v",
		newErrOptions("role", "003")...)
	ErrRoleNotExist = berror.NewErrDefinition(errCommonFormatRoleNotExist,
		newErrOptions("role", "004")...)
	ErrRoleMissingRole = berror.NewErrDefinition(errCommonFormatMissingRole,
		newErrOptions("role", "005")...)
)

var (
	ErrRoleBindingNamespaceBadRequest = berror.NewErrDefinition(errCommonFormatBadRequest,
		newErrOptions("role_binding_namespace", "001")...)
	ErrRoleBindingNamespaceFailMarshalJSON = berror.NewErrDefinition(errCommonFormatFailMarshalJSON,
		newErrOptions("role_binding_namespace", "002")...)
	ErrRoleBindingNamespaceMemberAlreadyExist = berror.NewErrDefinition(errCommonFormatMemberAlreadyExist,
		newErrOptions("role_binding_namespace", "003")...)
	ErrRoleBindingNamespaceMemberOrRoleNotExist = berror.NewErrDefinition(errCommonFormatMemberOrRoleNotExist,
		newErrOptions("role_binding_namespace", "004")...)
	ErrRoleBindingNamespaceRoleNotExist = berror.NewErrDefinition(errCommonFormatRoleNotExist,
		newErrOptions("role_binding_namespace", "005")...)
	ErrRoleBindingNamespaceEmptyMemberToBind = berror.NewErrDefinition(errCommonFormatEmptyMemberToBind,
		newErrOptions("role_binding_namespace", "006")...)
	ErrRoleBindingNamespaceEmptyMemberToUnbind = berror.NewErrDefinition(errCommonFormatEmptyMemberToUnbind,
		newErrOptions("role_binding_namespace", "007")...)
	ErrRoleBindingNamespaceMissingRole = berror.NewErrDefinition(errCommonFormatMissingRole,
		newErrOptions("role_binding_namespace", "008")...)
)

var (
	ErrRoleBindingSchemaBadRequest = berror.NewErrDefinition(errCommonFormatBadRequest,
		newErrOptions("role_binding_schema", "001")...)
	ErrRoleBindingSchemaFailMarshalJSON = berror.NewErrDefinition(errCommonFormatFailMarshalJSON,
		newErrOptions("role_binding_schema", "002")...)
	ErrRoleBindingSchemaMemberAlreadyExist = berror.NewErrDefinition(errCommonFormatMemberAlreadyExist,
		newErrOptions("role_binding_schema", "003")...)
	ErrRoleBindingSchemaMemberOrRoleNotExist = berror.NewErrDefinition(errCommonFormatMemberOrRoleNotExist,
		newErrOptions("role_binding_schema", "004")...)
	ErrRoleBindingSchemaRoleNotExist = berror.NewErrDefinition(errCommonFormatRoleNotExist,
		newErrOptions("role_binding_schema", "005")...)
	ErrRoleBindingSchemaEmptyMemberToBind = berror.NewErrDefinition(errCommonFormatEmptyMemberToBind,
		newErrOptions("role_binding_schema", "006")...)
	ErrRoleBindingSchemaEmptyMemberToUnbind = berror.NewErrDefinition(errCommonFormatEmptyMemberToUnbind,
		newErrOptions("role_binding_schema", "007")...)
	ErrRoleBindingSchemaMissingProject = berror.NewErrDefinition("project is missing",
		newErrOptions("role_binding_schema", "008")...)
	ErrRoleBindingSchemaMissingSchema = berror.NewErrDefinition("schema is missing",
		newErrOptions("role_binding_schema", "009")...)
	ErrRoleBindingSchemaMissingRole = berror.NewErrDefinition(errCommonFormatMissingRole,
		newErrOptions("role_binding_schema", "010")...)
)

func newErrOptions(module string, code string) []berror.ErrDefinitionOption {
	return []berror.ErrDefinitionOption{
		berror.OptionErrDefinitionWithErrCode(fmt.Sprintf("alicatalogapis-%v-%v", module, code)),
		berror.OptionErrDefinitionWithDisabledStackTrace(),
	}
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
