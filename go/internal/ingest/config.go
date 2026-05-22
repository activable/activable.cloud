package ingest

import (
	"context"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
)

// Config holds the runtime configuration for the ingestion framework.
type Config struct {
	// DatabaseURL is the connection string for the PostgreSQL database.
	DatabaseURL string

	// GraphName is the Apache AGE graph name (typically "activable").
	GraphName string

	// PoolSize is the maximum number of database connections in the pool.
	PoolSize uint32

	// Regions is the list of AWS regions to ingest. If empty, discovery is performed.
	Regions []string

	// BatchSize is the number of resources to batch in a single FFI write call.
	BatchSize int
}

// LoadConfig loads the configuration from environment variables.
// Defaults:
// - ACTIVABLE_DB_URL: required
// - ACTIVABLE_GRAPH_NAME: "activable"
// - ACTIVABLE_POOL_SIZE: 20
// - ACTIVABLE_REGIONS: empty (triggers discovery)
// - ACTIVABLE_BATCH_SIZE: 500
func LoadConfig() (*Config, error) {
	dbURL := os.Getenv("ACTIVABLE_DB_URL")
	if dbURL == "" {
		return nil, fmt.Errorf("ACTIVABLE_DB_URL is required")
	}

	graphName := os.Getenv("ACTIVABLE_GRAPH_NAME")
	if graphName == "" {
		graphName = "activable"
	}

	poolSizeStr := os.Getenv("ACTIVABLE_POOL_SIZE")
	poolSize := uint32(20)
	if poolSizeStr != "" {
		ps, err := strconv.ParseUint(poolSizeStr, 10, 32)
		if err != nil {
			return nil, fmt.Errorf("ACTIVABLE_POOL_SIZE must be a valid unsigned integer: %w", err)
		}
		poolSize = uint32(ps)
	}

	regionsStr := os.Getenv("ACTIVABLE_REGIONS")
	var regions []string
	if regionsStr != "" {
		regions = strings.Split(regionsStr, ",")
		// Trim whitespace from each region
		for i := range regions {
			regions[i] = strings.TrimSpace(regions[i])
		}
	}

	batchSizeStr := os.Getenv("ACTIVABLE_BATCH_SIZE")
	batchSize := 500
	if batchSizeStr != "" {
		bs, err := strconv.Atoi(batchSizeStr)
		if err != nil {
			return nil, fmt.Errorf("ACTIVABLE_BATCH_SIZE must be a valid integer: %w", err)
		}
		batchSize = bs
	}

	return &Config{
		DatabaseURL: dbURL,
		GraphName:   graphName,
		PoolSize:    poolSize,
		Regions:     regions,
		BatchSize:   batchSize,
	}, nil
}

// Redacted returns a copy of the config with the password component of the database URL masked.
// Safe for logging.
func (c *Config) Redacted() *Config {
	redacted := *c
	// Mask password in database URL for logging
	if strings.Contains(redacted.DatabaseURL, "@") {
		parts := strings.Split(redacted.DatabaseURL, "@")
		if len(parts) == 2 {
			// Replace everything between :// and the last : before @
			userPassPart := parts[0]
			hostPart := parts[1]
			if strings.Contains(userPassPart, ":") {
				userPart := strings.Split(userPassPart, ":")[0]
				redacted.DatabaseURL = userPart + ":***@" + hostPart
			}
		}
	}
	return &redacted
}

// DiscoverRegions enumerates the enabled AWS regions for the caller's account
// using the EC2 DescribeRegions API. Returns only regions with opt-in status
// "opt-in-not-required" or "opted-in".
func DiscoverRegions(ctx context.Context, cfg aws.Config) ([]string, error) {
	client := ec2.NewFromConfig(cfg)

	// Call DescribeRegions without filters to get all available regions
	// In production, you might filter by OptInStatus: "opt-in-not-required" or "opted-in"
	out, err := client.DescribeRegions(ctx, &ec2.DescribeRegionsInput{})
	if err != nil {
		return nil, fmt.Errorf("DescribeRegions failed: %w", err)
	}

	regions := make([]string, 0, len(out.Regions))
	for _, region := range out.Regions {
		if region.RegionName != nil && region.OptInStatus != nil {
			// Only include regions that are enabled
			optInStatus := *region.OptInStatus
			if optInStatus == "opt-in-not-required" || optInStatus == "opted-in" {
				regions = append(regions, *region.RegionName)
			}
		}
	}

	return regions, nil
}

// EnabledRegions returns the list of regions to enumerate for this runtime.
// If Config.Regions is non-empty, returns it directly.
// Otherwise, calls DiscoverRegions and caches the result in r.enabledRegions.
func (r *Runtime) EnabledRegions(ctx context.Context) ([]string, error) {
	// If already cached, return it
	if len(r.enabledRegions) > 0 {
		return r.enabledRegions, nil
	}

	// If explicitly configured, use those regions
	if len(r.config.Regions) > 0 {
		r.enabledRegions = r.config.Regions
		return r.enabledRegions, nil
	}

	// Otherwise, discover enabled regions via EC2 API
	cfg, err := config.LoadDefaultConfig(ctx)
	if err != nil {
		return nil, fmt.Errorf("LoadDefaultConfig failed: %w", err)
	}

	discovered, err := DiscoverRegions(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("region discovery failed: %w", err)
	}

	r.enabledRegions = discovered
	return r.enabledRegions, nil
}
