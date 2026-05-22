package main

import (
	"fmt"
	"log/slog"
	"os"
	"runtime"

	"github.com/activable-cloud/activable.cloud/bindings/activable"
	"github.com/activable-cloud/activable.cloud/go/internal/api/graphql"
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

var serveCmd = &cobra.Command{
	Use:   "serve",
	Short: "Start the GraphQL API server",
	Long:  "Starts the GraphQL API server on port 8080, wrapping Rust graph primitives via UniFFI.",
	RunE: func(cmd *cobra.Command, args []string) error {
		logger := slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{
			Level: slog.LevelInfo,
		}))

		// Initialize FFI runtime from environment variables
		dbHost := os.Getenv("DB_HOST")
		if dbHost == "" {
			dbHost = "localhost"
		}
		dbPort := uint16(5432)
		if portStr := os.Getenv("DB_PORT"); portStr != "" {
			fmt.Sscanf(portStr, "%d", &dbPort)
		}
		dbUser := os.Getenv("DB_USER")
		if dbUser == "" {
			dbUser = "postgres"
		}
		dbPassword := os.Getenv("DB_PASSWORD")
		if dbPassword == "" {
			dbPassword = "postgres"
		}
		dbName := os.Getenv("DB_NAME")
		if dbName == "" {
			dbName = "graph"
		}
		graphName := os.Getenv("GRAPH_NAME")
		if graphName == "" {
			graphName = "default"
		}

		logger.Info("Initializing FFI runtime",
			"db_host", dbHost,
			"db_port", dbPort,
			"db_user", dbUser,
			"db_name", dbName,
			"graph_name", graphName,
		)

		// Initialize the Rust FFI runtime
		initErr := activable.GraphInitialize(
			dbHost,
			dbPort,
			dbUser,
			dbPassword,
			dbName,
			100, // max_connections
			graphName,
		)
		if initErr != "" {
			return fmt.Errorf("failed to initialize FFI runtime: %s", initErr)
		}

		// Start GraphQL server
		server := graphql.NewServer(":8080", logger)
		logger.Info("Starting GraphQL server on port 8080")
		return server.Start()
	},
}

func init() {
	rootCmd.AddCommand(verifyCmd)
	rootCmd.AddCommand(ingestCmd)
	rootCmd.AddCommand(serveCmd)
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}
