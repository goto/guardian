package maxcompute

import (
	"errors"
	"fmt"
	"strings"
	"unicode"
)

const (
	accountIdPrefix     = "RAM$"
	accountIdUserPrefix = ":"
	accountIdRolePrefix = ":role/"
	arnRolePrefix       = "acs:ram::"
)

// ---------------------------------------------------------------------------------------------------------------------
// User account (RAM$5123xxx:2123xxx)
// ---------------------------------------------------------------------------------------------------------------------

type userAccountId struct {
	accountId string
	userId    string
}

func (a *userAccountId) account() string {
	return fmt.Sprintf("%s%s%s%s", accountIdPrefix, a.accountId, accountIdUserPrefix, a.userId) // RAM$5123xxx:2123xxx
}

func parseUserAccountId(in string) (*userAccountId, error) { // RAM$5123xxx:2123xxx
	in = strings.TrimSpace(in)
	if in == "" {
		return nil, errors.New("user account id is empty")
	}
	tmp := strings.ReplaceAll(strings.ToLower(in), strings.ToLower(accountIdPrefix), "") // 5123xxx:2123xxx
	if tmp == strings.ToLower(in) {
		return nil, fmt.Errorf("invalid user account id: '%s'", in)
	}
	tmpS := strings.Split(tmp, accountIdUserPrefix) // [0] 5123xxx, [1] 2123xxx
	if len(tmpS) != 2 {
		return nil, fmt.Errorf("invalid details from user account id: '%s'", in)
	}
	ret := userAccountId{
		accountId: tmpS[0], // 5123xxx
		userId:    tmpS[1], // 2123xxx
	}
	if ret.accountId == "" {
		return nil, fmt.Errorf("empty account id from user account id: '%s'", in)
	}
	if ret.userId == "" {
		return nil, fmt.Errorf("empty user id from user account id: '%s'", in)
	}
	for _, r := range ret.accountId {
		if !unicode.IsDigit(r) {
			return nil, fmt.Errorf("invalid account id from user account id: '%s'", in)
		}
	}
	for _, r := range ret.accountId {
		if !unicode.IsDigit(r) {
			return nil, fmt.Errorf("invalid user id from user account id: '%s'", in)
		}
	}
	return &ret, nil
}

// ---------------------------------------------------------------------------------------------------------------------
// Role account (RAM$5123xxx:role/role-name) (acs:ram::5123xxx:role/role-name)
// ---------------------------------------------------------------------------------------------------------------------

type roleAccountId struct {
	AccountId string
	RoleName  string
}

func (a *roleAccountId) account() string {
	return fmt.Sprintf("%s%s%s%s", accountIdPrefix, a.AccountId, accountIdRolePrefix, strings.ToLower(a.RoleName)) // RAM$5123xxx:role/role-name
}

func (a *roleAccountId) urn() string {
	return fmt.Sprintf("%s%s%s%s", arnRolePrefix, a.AccountId, accountIdRolePrefix, strings.ToLower(a.RoleName)) // acs:ram::5123xxx:role/role-name
}

func parseRoleAccountId(in string) (*roleAccountId, error) {
	in = strings.TrimSpace(in)
	if in == "" {
		return nil, errors.New("role account id is empty")
	}
	tmp := strings.ReplaceAll(strings.ToLower(in), strings.ToLower(accountIdPrefix), "") // 5123xxx:role/role-name
	tmp = strings.ReplaceAll(tmp, strings.ToLower(arnRolePrefix), "")                    // 5123xxx:role/role-name
	if tmp == strings.ToLower(in) {
		return nil, fmt.Errorf("invalid role account id: '%s'", in)
	}
	tmpS := strings.Split(tmp, accountIdRolePrefix) // [0] 5123xxx, [1] role-name
	if len(tmpS) != 2 {
		return nil, fmt.Errorf("invalid details from role account id: '%s'", in)
	}
	ret := roleAccountId{
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
// account
// ---------------------------------------------------------------------------------------------------------------------

func parseAccountId(in string) (string, error) {
	in = strings.TrimSpace(in)
	if in == "" {
		return "", errors.New("account is empty")
	}
	ua, err := parseUserAccountId(in)
	if err == nil {
		return ua.account(), nil
	}
	ra, err := parseRoleAccountId(in)
	if err == nil {
		return ra.account(), nil
	}
	return "", fmt.Errorf("invalid account: '%s'", in)
}
