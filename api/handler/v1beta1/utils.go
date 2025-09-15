package v1beta1

import "strings"

// parseCommaSeparatedValues splits comma-separated string values into arrays
// This handles cases where query parameters come as "value1,value2,value3"
// instead of repeated parameters "param=value1&param=value2&param=value3"
func parseCommaSeparatedValues(values []string) []string {
	if len(values) == 0 {
		return values
	}
	
	var result []string
	for _, v := range values {
		if strings.Contains(v, ",") {
			parts := strings.Split(v, ",")
			for _, part := range parts {
				trimmed := strings.TrimSpace(part)
				if trimmed != "" {
					result = append(result, trimmed)
				}
			}
		} else {
			if v != "" {
				result = append(result, v)
			}
		}
	}
	return result
}