package web

import (
	"net/http/httptest"
	"testing"
)

// TestGetIPWithTrustedProxies tests the secure IP extraction with trusted proxy validation.
func TestGetIPWithTrustedProxies(t *testing.T) {
	tests := []struct {
		name            string
		remoteAddr      string
		xForwardedFor   string
		xRealIP         string
		trustedProxies  []string
		expectedIP      string
		description     string
	}{
		{
			name:           "Direct connection (no proxy)",
			remoteAddr:     "192.168.1.100:12345",
			trustedProxies: []string{},
			expectedIP:     "192.168.1.100",
			description:    "Should extract IP from RemoteAddr when no proxy headers present",
		},
		{
			name:           "X-Forwarded-For but NO trusted proxies (secure default)",
			remoteAddr:     "10.0.0.1:8080",
			xForwardedFor:  "203.0.113.45",
			trustedProxies: []string{}, // Empty = don't trust any proxies
			expectedIP:     "10.0.0.1",
			description:    "Should ignore X-Forwarded-For when no trusted proxies configured (security)",
		},
		{
			name:           "X-Forwarded-For with trusted proxy",
			remoteAddr:     "10.0.0.1:8080",
			xForwardedFor:  "203.0.113.45",
			trustedProxies: []string{"10.0.0.1"}, // Trust this proxy
			expectedIP:     "203.0.113.45",
			description:    "Should use X-Forwarded-For when request comes from trusted proxy",
		},
		{
			name:           "X-Forwarded-For with multiple IPs and trusted proxy",
			remoteAddr:     "10.0.0.1:8080",
			xForwardedFor:  "203.0.113.45, 198.51.100.20, 192.0.2.30",
			trustedProxies: []string{"10.0.0.1"},
			expectedIP:     "203.0.113.45",
			description:    "Should extract the original client IP (first in chain) from trusted proxy",
		},
		{
			name:           "X-Forwarded-For with spaces and trusted proxy",
			remoteAddr:     "10.0.0.1:8080",
			xForwardedFor:  " 203.0.113.45 , 198.51.100.20 ",
			trustedProxies: []string{"10.0.0.1"},
			expectedIP:     "203.0.113.45",
			description:    "Should handle extra whitespace correctly",
		},
		{
			name:           "X-Real-IP with trusted proxy",
			remoteAddr:     "10.0.0.1:8080",
			xRealIP:        "203.0.113.45",
			trustedProxies: []string{"10.0.0.1"},
			expectedIP:     "203.0.113.45",
			description:    "Should use X-Real-IP when no X-Forwarded-For and proxy is trusted",
		},
		{
			name:           "X-Forwarded-For takes precedence over X-Real-IP (trusted proxy)",
			remoteAddr:     "10.0.0.1:8080",
			xForwardedFor:  "203.0.113.45",
			xRealIP:        "198.51.100.20",
			trustedProxies: []string{"10.0.0.1"},
			expectedIP:     "203.0.113.45",
			description:    "X-Forwarded-For should have priority when from trusted proxy",
		},
		{
			name:           "Untrusted proxy attempting to spoof IP",
			remoteAddr:     "99.99.99.99:8080", // Not in trusted list
			xForwardedFor:  "203.0.113.45",     // Attacker trying to spoof
			trustedProxies: []string{"10.0.0.1"},
			expectedIP:     "99.99.99.99",
			description:    "Should ignore X-Forwarded-For from untrusted source (SECURITY)",
		},
		{
			name:           "Multiple trusted proxies",
			remoteAddr:     "10.0.0.2:8080",
			xForwardedFor:  "203.0.113.45",
			trustedProxies: []string{"10.0.0.1", "10.0.0.2", "10.0.0.3"},
			expectedIP:     "203.0.113.45",
			description:    "Should work with multiple trusted proxy IPs",
		},
		{
			name:           "IPv6 address",
			remoteAddr:     "[2001:db8::1]:12345",
			trustedProxies: []string{},
			expectedIP:     "2001:db8::1",
			description:    "Should handle IPv6 addresses correctly",
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

			// Execute the function with trusted proxies
			result := getIPWithTrustedProxies(req, tt.trustedProxies)

			// Verify the result
			if result != tt.expectedIP {
				t.Errorf("%s\nExpected IP: %s\nGot: %s\nDescription: %s",
					tt.name, tt.expectedIP, result, tt.description)
			}
		})
	}
}

// TestGetIPWithTrustedProxies_EdgeCases tests edge cases and security scenarios.
func TestGetIPWithTrustedProxies_EdgeCases(t *testing.T) {
	t.Run("Empty X-Forwarded-For should fall back", func(t *testing.T) {
		req := httptest.NewRequest("GET", "http://example.com", nil)
		req.RemoteAddr = "192.168.1.1:8080"
		req.Header.Set("X-Forwarded-For", "")
		trustedProxies := []string{"192.168.1.1"}

		result := getIPWithTrustedProxies(req, trustedProxies)
		expected := "192.168.1.1"

		if result != expected {
			t.Errorf("Expected %s, got %s", expected, result)
		}
	})

	t.Run("Malformed RemoteAddr (no port)", func(t *testing.T) {
		req := httptest.NewRequest("GET", "http://example.com", nil)
		req.RemoteAddr = "192.168.1.1"

		result := getIPWithTrustedProxies(req, []string{})
		expected := "192.168.1.1"

		if result != expected {
			t.Errorf("Expected %s, got %s", expected, result)
		}
	})

	t.Run("Nil trusted proxies (secure default)", func(t *testing.T) {
		req := httptest.NewRequest("GET", "http://example.com", nil)
		req.RemoteAddr = "10.0.0.1:8080"
		req.Header.Set("X-Forwarded-For", "203.0.113.45")

		result := getIPWithTrustedProxies(req, nil)
		expected := "10.0.0.1" // Should ignore X-Forwarded-For

		if result != expected {
			t.Errorf("Expected %s (secure default), got %s", expected, result)
		}
	})

	t.Run("Invalid IP in X-Forwarded-For with trusted proxy", func(t *testing.T) {
		req := httptest.NewRequest("GET", "http://example.com", nil)
		req.RemoteAddr = "10.0.0.1:8080"
		req.Header.Set("X-Forwarded-For", "not-an-ip")
		req.Header.Set("X-Real-IP", "203.0.113.45")
		trustedProxies := []string{"10.0.0.1"}

		result := getIPWithTrustedProxies(req, trustedProxies)
		// Should fall back to X-Real-IP or RemoteAddr
		if result != "203.0.113.45" && result != "10.0.0.1" {
			t.Errorf("Expected fallback IP, got %s", result)
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
