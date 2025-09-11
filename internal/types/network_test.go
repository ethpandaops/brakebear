package types

import (
	"strings"
	"testing"
)

func TestValidateCIDRRange(t *testing.T) {
	t.Parallel()

	tests := getValidateCIDRRangeTestCases()

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			err := ValidateCIDRRange(tt.cidr)

			if tt.expectError {
				if err == nil {
					t.Errorf("expected error for CIDR '%s', but got none", tt.cidr)
				} else if tt.errorContains != "" && !strings.Contains(err.Error(), tt.errorContains) {
					t.Errorf("expected error to contain '%s', but got: %v", tt.errorContains, err)
				}
			} else {
				if err != nil {
					t.Errorf("unexpected error for CIDR '%s': %v", tt.cidr, err)
				}
			}
		})
	}
}

func getValidateCIDRRangeTestCases() []struct {
	name          string
	cidr          string
	expectError   bool
	errorContains string
} {
	return []struct {
		name          string
		cidr          string
		expectError   bool
		errorContains string
	}{
		// Valid IPv4 cases
		{"valid IPv4 CIDR", "192.168.1.0/24", false, ""},
		{"valid IPv4 host", "10.0.0.1/32", false, ""},
		{"valid IPv4 network", "172.16.0.0/12", false, ""},
		// Valid IPv6 cases
		{"valid IPv6 CIDR", "2001:db8::/32", false, ""},
		{"valid IPv6 host", "2001:db8::1/128", false, ""},
		{"valid IPv6 ULA", "fc00::/7", false, ""},
		{"valid IPv6 link-local", "fe80::/10", false, ""},
		// Invalid cases
		{"empty CIDR", "", true, "cannot be empty"},
		{"whitespace only", "   ", true, "cannot be empty"},
		{"invalid IPv4 format", "192.168.1", true, "invalid CIDR format"},
		{"invalid IPv6 format", "2001:db8::1/", true, "invalid CIDR format"},
		{"IPv4 prefix too large", "192.168.1.0/33", true, "invalid CIDR format"},
		{"IPv6 prefix too large", "2001:db8::/129", true, "invalid CIDR format"},
	}
}

func TestGetDefaultPrivateRanges(t *testing.T) {
	t.Parallel()

	ranges := GetDefaultPrivateRanges()

	expectedRanges := []string{
		"10.0.0.0/8",
		"172.16.0.0/12",
		"192.168.0.0/16",
		"fc00::/7",
		"fe80::/10",
	}

	if len(ranges) != len(expectedRanges) {
		t.Errorf("expected %d ranges, got %d", len(expectedRanges), len(ranges))
	}

	// Verify each expected range is present
	for _, expected := range expectedRanges {
		found := false
		for _, actual := range ranges {
			if actual == expected {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("expected range '%s' not found in private ranges", expected)
		}
	}

	// Validate that all returned ranges are valid CIDR ranges
	for i, cidr := range ranges {
		if err := ValidateCIDRRange(cidr); err != nil {
			t.Errorf("invalid CIDR range at index %d: %s - %v", i, cidr, err)
		}
	}
}
