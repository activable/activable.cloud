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
	Short: "Activable — cognitive knowledge graph for cloud infrastructure",
	Long:  "Activable GraphQL API server. Ingestion is triggered via the triggerIngest GraphQL mutation.",
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

var serveCmd = &cobra.Command{
	Use:   "serve",
	Short: "Start the GraphQL API server",
	Long:  "Starts the GraphQL API server. Ingestion is triggered via the triggerIngest mutation, not a CLI command.",
	RunE: func(cmd *cobra.Command, args []string) error {
		port, _ := cmd.Flags().GetInt("port")
		dbHost, _ := cmd.Flags().GetString("db-host")
		dbUser, _ := cmd.Flags().GetString("db-user")
		dbPassword, _ := cmd.Flags().GetString("db-password")
		dbName, _ := cmd.Flags().GetString("db-name")
		graphName, _ := cmd.Flags().GetString("graph-name")
		logLevel, _ := cmd.Flags().GetString("log-level")
		maxConnections, _ := cmd.Flags().GetInt("max-connections")

		var logOpt slog.Level
		switch logLevel {
		case "debug":
			logOpt = slog.LevelDebug
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
			"db_name", dbName,
			"graph_name", graphName,
		)

		ffiClient := graphql.NewRealFFIClient()
		err := ffiClient.GraphInitialize(dbHost, dbUser, dbPassword, dbName, graphName, uint32(maxConnections))
		if err != nil {
			logger.Error("Failed to initialize graph", "error", err)
			return err
		}

		server := graphql.NewServer(ffiClient, port, logger)
		return server.Start()
	},
}

func init() {
	rootCmd.AddCommand(verifyCmd)
	rootCmd.AddCommand(serveCmd)
	// NOTE: No ingest subcommand. Ingestion is triggered via GraphQL mutation triggerIngest.

	serveCmd.Flags().IntP("port", "p", 8080, "Server port")
	serveCmd.Flags().String("db-host", os.Getenv("ACTIVABLE_DB_HOST"), "Database host")
	serveCmd.Flags().String("db-user", os.Getenv("ACTIVABLE_DB_USER"), "Database user")
	serveCmd.Flags().String("db-password", os.Getenv("ACTIVABLE_DB_PASSWORD"), "Database password")
	serveCmd.Flags().String("db-name", envOrDefault("ACTIVABLE_DB_NAME", "activable"), "Database name")
	serveCmd.Flags().String("graph-name", envOrDefault("ACTIVABLE_GRAPH_NAME", "cloud"), "Graph name")
	serveCmd.Flags().String("log-level", envOrDefault("ACTIVABLE_LOG_LEVEL", "info"), "Log level")
	serveCmd.Flags().Int("max-connections", 20, "Max database connections")
}

func envOrDefault(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}
