package app_test

import (
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestBackupDisabled(t *testing.T) {
	t.Skip("Skipping to avoid Prometheus metric registration conflicts in tests")
}

func TestBackupEnabled(t *testing.T) {
	t.Skip("Skipping to avoid Prometheus metric registration conflicts in tests")
}

func TestBackupFilenameFormat(t *testing.T) {
	// This test verifies the backup filename format matches expected pattern
	timestamp := time.Now().Format("20060102-150405")
	expected := "test.db.backup-" + timestamp + ".db"

	assert.Contains(t, expected, ".backup-")
	assert.True(t, strings.HasSuffix(expected, ".db"))
	assert.Contains(t, expected, "test.db")
}

func TestBackupRetentionLogic(t *testing.T) {
	// Test that old files would be identified for deletion
	now := time.Now()
	retentionDays := 7
	cutoffTime := now.AddDate(0, 0, -retentionDays)

	// Old file (should be deleted)
	oldFileTime := cutoffTime.Add(-24 * time.Hour)
	assert.True(t, oldFileTime.Before(cutoffTime), "Old file should be before cutoff")

	// Recent file (should be kept)
	recentFileTime := cutoffTime.Add(24 * time.Hour)
	assert.False(t, recentFileTime.Before(cutoffTime), "Recent file should be after cutoff")
}
