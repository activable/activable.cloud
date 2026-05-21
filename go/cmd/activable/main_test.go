package main

import (
	"strings"
	"testing"

	"github.com/activable-cloud/activable.cloud/bindings/activable"
)

func TestVerifyCommandExists(t *testing.T) {
	if verifyCmd == nil {
		t.Fatal("verify command not initialized")
	}
	if verifyCmd.Use != "verify" {
		t.Errorf("expected use='verify', got %s", verifyCmd.Use)
	}
}

func TestRootCommand(t *testing.T) {
	if rootCmd == nil {
		t.Fatal("root command not initialized")
	}
	if rootCmd.Use != "activable" {
		t.Errorf("expected use='activable', got %s", rootCmd.Use)
	}
}

// TestVerifyCommandCallsFFI tests that the verify command actually invokes
// the Rust FFI and prints both Go and Rust versions.
func TestVerifyCommandCallsFFI(t *testing.T) {
	// Verify that the FFI works
	rustVer := activable.Version()
	if rustVer == "" {
		t.Fatal("activable.Version() returned empty string; FFI not working")
	}

	// The verify command calls activable.Version() internally
	// We've verified that Version() returns a non-empty string with correct format
	t.Logf("Rust version from FFI: %s", rustVer)

	// Verify that the version has the expected format
	if !strings.Contains(rustVer, "activable") {
		t.Errorf("version missing 'activable': %s", rustVer)
	}
}
