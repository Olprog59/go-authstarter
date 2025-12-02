package mocks

// MockMetrics is a mock implementation of metrics recorder for testing
type MockMetrics struct {
	AccountLockoutCalls int
	RegistrationCalls   int
}

func NewMockMetrics() *MockMetrics {
	return &MockMetrics{}
}

func (m *MockMetrics) RecordAccountLockout() {
	m.AccountLockoutCalls++
}

func (m *MockMetrics) RecordRegistration() {
	m.RegistrationCalls++
}
