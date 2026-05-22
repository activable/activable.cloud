package ingest

import (
	"context"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
)

// Config holds the ingestion configuration loaded from environment variables.
type Config struct {
	DatabaseURL string
	PoolSize    int
	GraphName   string
	Regions     []string
	BatchSize   int
}

// LoadConfig loads ingestion configuration from environment variables.
// Defaults:
// - PoolSize: 10
// - BatchSize: 500
func LoadConfig() (Config, error) {
	cfg := Config{
		DatabaseURL: os.Getenv("ACTIVABLE_DB_URL"),
		GraphName:   os.Getenv("ACTIVABLE_GRAPH_NAME"),
		PoolSize:    10,
		BatchSize:   500,
	}

	if cfg.DatabaseURL == "" {
		return Config{}, fmt.Errorf("ACTIVABLE_DB_URL not set")
	}
	if cfg.GraphName == "" {
		return Config{}, fmt.Errorf("ACTIVABLE_GRAPH_NAME not set")
	}

	// Parse optional PoolSize
	if poolSizeStr := os.Getenv("ACTIVABLE_POOL_SIZE"); poolSizeStr != "" {
		poolSize, err := strconv.Atoi(poolSizeStr)
		if err != nil {
			return Config{}, fmt.Errorf("invalid ACTIVABLE_POOL_SIZE: %w", err)
		}
		cfg.PoolSize = poolSize
	}

	// Parse optional BatchSize
	if batchSizeStr := os.Getenv("ACTIVABLE_BATCH_SIZE"); batchSizeStr != "" {
		batchSize, err := strconv.Atoi(batchSizeStr)
		if err != nil {
			return Config{}, fmt.Errorf("invalid ACTIVABLE_BATCH_SIZE: %w", err)
		}
		cfg.BatchSize = batchSize
	}

	// Parse optional Regions
	if regionsStr := os.Getenv("ACTIVABLE_REGIONS"); regionsStr != "" {
		regions := strings.Split(regionsStr, ",")
		for i, r := range regions {
			regions[i] = strings.TrimSpace(r)
		}
		cfg.Regions = regions
	}

	return cfg, nil
}

// Redacted returns a copy of the config with the database password masked.
func (c Config) Redacted() Config {
	redacted := c
	// Mask password in connection string for logging
	if idx := strings.Index(redacted.DatabaseURL, ":"); idx != -1 {
		if atIdx := strings.Index(redacted.DatabaseURL[idx:], "@"); atIdx != -1 {
			// Replace password with masked value
			redacted.DatabaseURL = redacted.DatabaseURL[:idx+1] + "***" + redacted.DatabaseURL[idx+atIdx:]
		}
	}
	return redacted
}

// EnabledRegions returns the list of enabled AWS regions for the caller.
// If regions are explicitly configured, returns those.
// Otherwise, calls ec2:DescribeRegions to discover enabled regions.
func EnabledRegions(ctx context.Context, regions []string) ([]string, error) {
	if len(regions) > 0 {
		return regions, nil
	}

	// Load AWS config and call DescribeRegions
	cfg, err := config.LoadDefaultConfig(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to load AWS config: %w", err)
	}

	ec2Client := ec2.NewFromConfig(cfg)
	result, err := ec2Client.DescribeRegions(ctx, &ec2.DescribeRegionsInput{
		AllRegions: nil, // Only regions enabled for the account
	})
	if err != nil {
		return nil, fmt.Errorf("failed to describe regions: %w", err)
	}

	enabledRegions := make([]string, 0, len(result.Regions))
	for _, region := range result.Regions {
		if region.RegionName != nil {
			enabledRegions = append(enabledRegions, *region.RegionName)
		}
	}

	return enabledRegions, nil
}
