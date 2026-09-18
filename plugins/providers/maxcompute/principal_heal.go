package maxcompute

import (
	"regexp"
	"strings"

	"github.com/goto/guardian/domain"
)

var (
	reV4UserDoesNotExist      = regexp.MustCompile(`(?i)the user (v4_\d+) does not exist`)
	rePrincipalDoesNotExist   = regexp.MustCompile(`(?i)Principal '[^']+' does not exist in the project`)
)

// MissingPrincipalInfo describes a MaxCompute grant failure caused by the
// account not being a project member. AliCloud sometimes reports a stale
// v4_<id> principal instead of the real RAM$ account on the grant.
type MissingPrincipalInfo struct {
	// StaleUser is the v4_<id> reported by AliCloud when present; empty for
	// Principal 'RAM$...' does not exist errors.
	StaleUser string
}

// MatchMissingPrincipalError returns true when err indicates the grant
// principal is missing from the MaxCompute project.
func MatchMissingPrincipalError(err error) (MissingPrincipalInfo, bool) {
	if err == nil {
		return MissingPrincipalInfo{}, false
	}
	msg := err.Error()
	if m := reV4UserDoesNotExist.FindStringSubmatch(msg); len(m) == 2 {
		return MissingPrincipalInfo{StaleUser: m[1]}, true
	}
	if rePrincipalDoesNotExist.MatchString(msg) {
		return MissingPrincipalInfo{}, true
	}
	return MissingPrincipalInfo{}, false
}

// ProjectNameFromResource returns the MaxCompute project name encoded in the
// resource URN (project as-is; schema/table = first segment).
func ProjectNameFromResource(r *domain.Resource) (string, bool) {
	if r == nil || r.ProviderType != sourceName {
		return "", false
	}
	switch r.Type {
	case resourceTypeProject:
		if r.URN == "" {
			return "", false
		}
		return r.URN, true
	case resourceTypeSchema, resourceTypeTable:
		project := strings.Split(r.URN, ".")[0]
		if project == "" {
			return "", false
		}
		return project, true
	default:
		return "", false
	}
}
