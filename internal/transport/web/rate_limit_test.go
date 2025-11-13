package web

import (
	"net/http/httptest"
	"testing"
)

// TestGetIP tests the getIP function with various header configurations.
func TestGetIP(t *testing.T) {
	tests := []struct {
		name              string
		remoteAddr        string
		xForwardedFor     string
		xRealIP           string
		expectedIP        string
		description       string
	}{
		{
			name:        "Direct connection (no proxy)",
			remoteAddr:  "192.168.1.100:12345",
			expectedIP:  "192.168.1.100",
			description: "Should extract IP from RemoteAddr when no proxy headers present",
		},
		{
			name:          "X-Forwarded-For with single IP",
			remoteAddr:    "10.0.0.1:8080",
			xForwardedFor: "203.0.113.45",
			expectedIP:    "203.0.113.45",
			description:   "Should use first IP from X-Forwarded-For",
		},
		{
			name:          "X-Forwarded-For with multiple IPs (proxy chain)",
			remoteAddr:    "10.0.0.1:8080",
			xForwardedFor: "203.0.113.45, 198.51.100.20, 192.0.2.30",
			expectedIP:    "203.0.113.45",
			description:   "Should extract the original client IP (first in chain)",
		},
		{
			name:          "X-Forwarded-For with spaces",
			remoteAddr:    "10.0.0.1:8080",
			xForwardedFor: " 203.0.113.45 , 198.51.100.20 ",
			expectedIP:    "203.0.113.45",
			description:   "Should handle extra whitespace correctly",
		},
		{
			name:        "X-Real-IP header",
			remoteAddr:  "10.0.0.1:8080",
			xRealIP:     "203.0.113.45",
			expectedIP:  "203.0.113.45",
			description: "Should use X-Real-IP when no X-Forwarded-For",
		},
		{
			name:          "X-Forwarded-For takes precedence over X-Real-IP",
			remoteAddr:    "10.0.0.1:8080",
			xForwardedFor: "203.0.113.45",
			xRealIP:       "198.51.100.20",
			expectedIP:    "203.0.113.45",
			description:   "X-Forwarded-For should have priority",
		},
		{
			name:          "Invalid X-Forwarded-For falls back to X-Real-IP",
			remoteAddr:    "10.0.0.1:8080",
			xForwardedFor: "invalid-ip-address",
			xRealIP:       "203.0.113.45",
			expectedIP:    "203.0.113.45",
			description:   "Should fall back when X-Forwarded-For is malformed",
		},
		{
			name:        "IPv6 address",
			remoteAddr:  "[2001:db8::1]:12345",
			expectedIP:  "2001:db8::1",
			description: "Should handle IPv6 addresses correctly",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create a mock HTTP request
			req := httptest.NewRequest("GET", "http://example.com", nil)
			req.RemoteAddr = tt.remoteAddr

			// Set headers if provided
			if tt.xForwardedFor != "" {
				req.Header.Set("X-Forwarded-For", tt.xForwardedFor)
			}
			if tt.xRealIP != "" {
				req.Header.Set("X-Real-IP", tt.xRealIP)
			}

			// Execute the function
			result := getIP(req)

			// Verify the result
			if result != tt.expectedIP {
				t.Errorf("%s\nExpected IP: %s\nGot: %s\nDescription: %s",
					tt.name, tt.expectedIP, result, tt.description)
			}
		})
	}
}

// TestGetIP_EdgeCases tests edge cases and security scenarios.
func TestGetIP_EdgeCases(t *testing.T) {
	t.Run("Empty X-Forwarded-For should fall back", func(t *testing.T) {
		req := httptest.NewRequest("GET", "http://example.com", nil)
		req.RemoteAddr = "192.168.1.1:8080"
		req.Header.Set("X-Forwarded-For", "")

		result := getIP(req)
		expected := "192.168.1.1"

		if result != expected {
			t.Errorf("Expected %s, got %s", expected, result)
		}
	})

	t.Run("Malformed RemoteAddr (no port)", func(t *testing.T) {
		req := httptest.NewRequest("GET", "http://example.com", nil)
		req.RemoteAddr = "192.168.1.1"

		result := getIP(req)
		expected := "192.168.1.1"

		if result != expected {
			t.Errorf("Expected %s, got %s", expected, result)
		}
	})
}

// TestHashIP tests the IP hashing function.
func TestHashIP(t *testing.T) {
	t.Run("Same IP produces same hash", func(t *testing.T) {
		ip := "192.168.1.1"
		hash1 := hashIP(ip)
		hash2 := hashIP(ip)

		if hash1 != hash2 {
			t.Errorf("Same IP should produce consistent hash. Got %s and %s", hash1, hash2)
		}
	})

	t.Run("Different IPs produce different hashes", func(t *testing.T) {
		ip1 := "192.168.1.1"
		ip2 := "192.168.1.2"

		hash1 := hashIP(ip1)
		hash2 := hashIP(ip2)

		if hash1 == hash2 {
			t.Errorf("Different IPs should produce different hashes")
		}
	})

	t.Run("Hash is deterministic (SHA-256)", func(t *testing.T) {
		ip := "203.0.113.45"
		expectedLength := 64 // SHA-256 hex string is 64 characters

		hash := hashIP(ip)

		if len(hash) != expectedLength {
			t.Errorf("Expected hash length %d, got %d", expectedLength, len(hash))
		}
	})
}
