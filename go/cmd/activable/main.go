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
	Long:  "Starts the GraphQL API server for querying the attack graph.",
	RunE: func(cmd *cobra.Command, args []string) error {
		// Get flags
		port, _ := cmd.Flags().GetInt("port")
		dbHost, _ := cmd.Flags().GetString("db-host")
		dbPort, _ := cmd.Flags().GetInt("db-port")
		dbUser, _ := cmd.Flags().GetString("db-user")
		dbPassword, _ := cmd.Flags().GetString("db-password")
		dbName, _ := cmd.Flags().GetString("db-name")
		graphName, _ := cmd.Flags().GetString("graph-name")
		logLevel, _ := cmd.Flags().GetString("log-level")
		maxConnections, _ := cmd.Flags().GetInt("max-connections")

		// Create logger
		var logOpt slog.Level
		switch logLevel {
		case "debug":
			logOpt = slog.LevelDebug
		case "info":
			logOpt = slog.LevelInfo
		case "warn":
			logOpt = slog.LevelWarn
		case "error":
			logOpt = slog.LevelError
		default:
			logOpt = slog.LevelInfo
		}

		handler := slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: logOpt})
		logger := slog.New(handler)

		logger.Info("Starting Activable GraphQL server",
			"port", port,
			"db_host", dbHost,
			"db_port", dbPort,
			"db_name", dbName,
			"graph_name", graphName,
		)

		// Initialize FFI
		ffiClient := graphql.NewRealFFIClient()
		err := ffiClient.GraphInitialize(dbHost, dbUser, dbPassword, dbName, graphName, uint32(maxConnections))
		if err != nil {
			logger.Error("Failed to initialize graph", "error", err)
			return err
		}

		// Start server
		server := graphql.NewServer(ffiClient, port, logger)
		return server.Start()
	},
}

func init() {
	rootCmd.AddCommand(verifyCmd)
	rootCmd.AddCommand(ingestCmd)
	rootCmd.AddCommand(serveCmd)

	// Serve command flags
	serveCmd.Flags().IntP("port", "p", 8080, "Server port")
	serveCmd.Flags().String("db-host", "localhost", "Database host")
	serveCmd.Flags().Int("db-port", 5432, "Database port")
	serveCmd.Flags().String("db-user", "activable", "Database user")
	serveCmd.Flags().String("db-password", "", "Database password")
	serveCmd.Flags().String("db-name", "activable", "Database name")
	serveCmd.Flags().String("graph-name", "activable", "Graph name")
	serveCmd.Flags().String("log-level", "info", "Log level (debug, info, warn, error)")
	serveCmd.Flags().Int("max-connections", 20, "Max database connections")
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}
