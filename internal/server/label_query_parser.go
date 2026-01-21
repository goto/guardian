package server

import (
	"encoding/json"
	"net/http"
	"strings"
)

// labelQueryParser extracts labels.KEY=VALUE query params and passes them via gRPC metadata
// This bypasses grpc-gateway's limitation with parsing map<string, MessageType> from query params
func labelQueryParser(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		query := r.URL.Query()
		labelsMap := make(map[string][]string)

		// Extract label parameters
		for key, values := range query {
			if strings.HasPrefix(key, "labels.") {
				labelKey := strings.TrimPrefix(key, "labels.")
				labelsMap[labelKey] = values
				// Remove from query to avoid grpc-gateway errors
				query.Del(key)
			}
		}

		// If labels were found, pass them via header
		if len(labelsMap) > 0 {
			labelsJSON, err := json.Marshal(labelsMap)
			if err == nil {
				r.Header.Set("X-Guardian-Labels", string(labelsJSON))
			}
		}

		// Update query string without label params
		r.URL.RawQuery = query.Encode()

		next.ServeHTTP(w, r)
	})
}
