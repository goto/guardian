package maxcompute

import (
	"errors"
	"fmt"
	"strings"
	"unicode"
)

const (
	AccountIdPrefix     = "RAM$"
	AccountIdUserPrefix = ":"
	AccountIdRolePrefix = ":role/"
	ARNRolePrefix       = "acs:ram::"
)

// ---------------------------------------------------------------------------------------------------------------------
// User Account (RAM$5123xxx:2123xxx)
// ---------------------------------------------------------------------------------------------------------------------

type UserAccountId struct {
	AccountId string
	UserId    string
}

func (a *UserAccountId) Account() string {
	return fmt.Sprintf("%s%s%s%s", AccountIdPrefix, a.AccountId, AccountIdUserPrefix, a.UserId) // RAM$5123xxx:2123xxx
}

func ParseUserAccountId(in string) (*UserAccountId, error) { // RAM$5123xxx:2123xxx
	in = strings.TrimSpace(in)
	if in == "" {
		return nil, errors.New("user account id is empty")
	}
	tmp := strings.ReplaceAll(strings.ToLower(in), strings.ToLower(AccountIdPrefix), "") // 5123xxx:2123xxx
	if tmp == strings.ToLower(in) {
		return nil, fmt.Errorf("invalid user account id: '%s'", in)
	}
	tmpS := strings.Split(tmp, AccountIdUserPrefix) // [0] 5123xxx, [1] 2123xxx
	if len(tmpS) != 2 {
		return nil, fmt.Errorf("invalid details from user account id: '%s'", in)
	}
	ret := UserAccountId{
		AccountId: tmpS[0], // 5123xxx
		UserId:    tmpS[1], // 2123xxx
	}
	if ret.AccountId == "" {
		return nil, fmt.Errorf("empty account id from user account id: '%s'", in)
	}
	if ret.UserId == "" {
		return nil, fmt.Errorf("empty user id from user account id: '%s'", in)
	}
	for _, r := range ret.AccountId {
		if !unicode.IsDigit(r) {
			return nil, fmt.Errorf("invalid account id from user account id: '%s'", in)
		}
	}
	for _, r := range ret.AccountId {
		if !unicode.IsDigit(r) {
			return nil, fmt.Errorf("invalid user id from user account id: '%s'", in)
		}
	}
	return &ret, nil
}

// ---------------------------------------------------------------------------------------------------------------------
// Role Account (RAM$5123xxx:role/role-name) (acs:ram::5123xxx:role/role-name)
// ---------------------------------------------------------------------------------------------------------------------

type RoleAccountId struct {
	AccountId string
	RoleName  string
}

func (a *RoleAccountId) Account() string {
	return fmt.Sprintf("%s%s%s%s", AccountIdPrefix, a.AccountId, AccountIdRolePrefix, strings.ToLower(a.RoleName)) // RAM$5123xxx:role/role-name
}

func (a *RoleAccountId) URN() string {
	return fmt.Sprintf("%s%s%s%s", ARNRolePrefix, a.AccountId, AccountIdRolePrefix, strings.ToLower(a.RoleName)) // acs:ram::5123xxx:role/role-name
}

func ParseRoleAccountId(in string) (*RoleAccountId, error) {
	in = strings.TrimSpace(in)
	if in == "" {
		return nil, errors.New("role account id is empty")
	}
	tmp := strings.ReplaceAll(strings.ToLower(in), strings.ToLower(AccountIdPrefix), "") // 5123xxx:role/role-name
	tmp = strings.ReplaceAll(tmp, strings.ToLower(ARNRolePrefix), "")                    // 5123xxx:role/role-name
	if tmp == strings.ToLower(in) {
		return nil, fmt.Errorf("invalid role account id: '%s'", in)
	}
	tmpS := strings.Split(tmp, AccountIdRolePrefix) // [0] 5123xxx, [1] role-name
	if len(tmpS) != 2 {
		return nil, fmt.Errorf("invalid details from role account id: '%s'", in)
	}
	ret := RoleAccountId{
		AccountId: tmpS[0], // 5123xxx
		RoleName:  tmpS[1], // role-name
	}
	if ret.AccountId == "" {
		return nil, fmt.Errorf("empty account id from role account id: '%s'", in)
	}
	if ret.RoleName == "" {
		return nil, fmt.Errorf("empty role name from role account id: '%s'", in)
	}
	for _, r := range ret.AccountId {
		if !unicode.IsDigit(r) {
			return nil, fmt.Errorf("invalid account id from role account id: '%s'", in)
		}
	}
	return &ret, nil
}

// ---------------------------------------------------------------------------------------------------------------------
// Account
// ---------------------------------------------------------------------------------------------------------------------

func ParseAccountId(in string) (string, error) {
	in = strings.TrimSpace(in)
	if in == "" {
		return "", errors.New("account is empty")
	}
	ua, err := ParseUserAccountId(in)
	if err == nil {
		return ua.Account(), nil
	}
	ra, err := ParseRoleAccountId(in)
	if err == nil {
		return ra.Account(), nil
	}
	return "", fmt.Errorf("invalid account: '%s'", in)
}
