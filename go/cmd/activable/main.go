package main

import (
	"fmt"
	"os"
	"runtime"

	"github.com/activable-cloud/activable.cloud/bindings/activable"
	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:   "activable",
	Short: "Activable cloud attack-graph CLI",
	Long:  "activable is a tool for ingesting and querying cloud attack graphs.",
}

var verifyCmd = &cobra.Command{
	Use:   "verify",
	Short: "Verify installation (smoke test)",
	Long:  "Calls Rust version() via UniFFI and prints both Go and Rust versions.",
	RunE: func(cmd *cobra.Command, args []string) error {
		fmt.Printf("Go version: %s\n", runtime.Version())
		rustVer := activable.Version()
		fmt.Printf("Rust version: %s\n", rustVer)
		return nil
	},
}

var ingestCmd = &cobra.Command{
	Use:   "ingest",
	Short: "Ingest cloud provider data (not implemented)",
	RunE: func(cmd *cobra.Command, args []string) error {
		return fmt.Errorf("ingest command not yet implemented")
	},
}

func init() {
	rootCmd.AddCommand(verifyCmd)
	rootCmd.AddCommand(ingestCmd)
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}
