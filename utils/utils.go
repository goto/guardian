package utils

import (
	"fmt"

	"github.com/google/uuid"
)

func IsInteger(val float64) bool {
	return val == float64(int(val))
}

// MapToSlice converts map[string]string to []string
//
// Example:
//
//	Input: map[string]string{ "key1": "value1", "key2": "value2", "key3": "value3"}
//	Output: []string{"key1=value1", "key2=value2", "key3=value3"}
func MapToSlice(m map[string]string) []string {
	s := make([]string, len(m))
	i := 0
	for k, v := range m {
		s[i] = k + "=" + v
		i++
	}
	return s
}

// IsValidUUID returns true if uuid is valid
func IsValidUUID(u string) bool {
	_, err := uuid.Parse(u)
	return err == nil
}

// GetGlobalURN returns a GlobalURN for a given source, scope, kind and identifier
// format is urn:<source>:<scope>:<kind>:<identifier>
func GetGlobalURN(source, scope, kind, identifier string) string {
	return fmt.Sprintf("urn:%s:%s:%s:%s", source, scope, kind, identifier)
}
