package sts

import (
	"context"
	"testing"

	"github.com/activable-cloud/activable.cloud/go/internal/ingest"
)

// TestSTSIngesterService tests that the service name is correct.
func TestSTSIngesterService(t *testing.T) {
	ingester := NewSTSIngester(nil, "123456789012")
	if got := ingester.Service(); got != "sts" {
		t.Errorf("Service() = %q, want %q", got, "sts")
	}
}

// TestSTSIngesterRequiredIAMActions tests that required actions are returned.
func TestSTSIngesterRequiredIAMActions(t *testing.T) {
	ingester := NewSTSIngester(nil, "123456789012")
	actions := ingester.RequiredIAMActions()
	if len(actions) == 0 {
		t.Errorf("RequiredIAMActions() returned empty list, want non-empty")
	}
	if actions[0] != "sts:GetCallerIdentity" {
		t.Errorf("RequiredIAMActions()[0] = %q, want %q", actions[0], "sts:GetCallerIdentity")
	}
}

// TestSTSIngesterEnumerateEmitsAccountNode tests that Enumerate emits a single Account node.
func TestSTSIngesterEnumerateEmitsAccountNode(t *testing.T) {
	accountID := "123456789012"
	ingester := NewSTSIngester(nil, accountID)

	resourcesChan, errorsChan := ingester.Enumerate(context.Background(), "us-east-1")

	// Collect all resources
	var resources []ingest.ResourceSpec
	var errors []error

	for {
		select {
		case res, ok := <-resourcesChan:
			if !ok {
				resourcesChan = nil
			} else {
				resources = append(resources, res)
			}
		case err, ok := <-errorsChan:
			if !ok {
				errorsChan = nil
			} else {
				errors = append(errors, err)
			}
		}
		if resourcesChan == nil && errorsChan == nil {
			break
		}
	}

	// Check errors
	if len(errors) > 0 {
		t.Errorf("Enumerate() returned errors: %v", errors)
	}

	// Check resources
	if len(resources) != 1 {
		t.Errorf("Enumerate() returned %d resources, want 1", len(resources))
		return
	}

	res := resources[0]
	if res.Label != "Account" {
		t.Errorf("Label = %q, want %q", res.Label, "Account")
	}
	if res.ID != accountID {
		t.Errorf("ID = %q, want %q", res.ID, accountID)
	}

	if acctID, ok := res.Properties["account_id"]; !ok || acctID != accountID {
		t.Errorf("account_id property = %v, want %q", acctID, accountID)
	}
}

// TestSTSIngesterEnumerateHandlesMultipleCalls tests that multiple Enumerate calls work independently.
func TestSTSIngesterEnumerateHandlesMultipleCalls(t *testing.T) {
	accountID := "123456789012"
	ingester := NewSTSIngester(nil, accountID)

	// Call Enumerate twice with different regions
	resources1, errors1 := ingester.Enumerate(context.Background(), "us-east-1")
	resources2, errors2 := ingester.Enumerate(context.Background(), "eu-west-1")

	// Drain both channels
	count1 := 0
	for range resources1 {
		count1++
	}
	for range errors1 {
	}

	count2 := 0
	for range resources2 {
		count2++
	}
	for range errors2 {
	}

	if count1 != 1 {
		t.Errorf("First Enumerate returned %d resources, want 1", count1)
	}
	if count2 != 1 {
		t.Errorf("Second Enumerate returned %d resources, want 1", count2)
	}
}
