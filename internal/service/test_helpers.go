package service

import "strings"

// contains checks if substr is contained anywhere in s
func contains(s, substr string) bool {
	return strings.Contains(s, substr)
}
