# Developer Guide: Adding a New AWS Service Ingester

This guide walks you through adding a new AWS service ingester to the Activable graph system. By the end, you'll have a fully tested, integrated ingester that fetches resources from AWS, transforms them into graph nodes and edges, and loads them into the graph database.

## When to Add a New Service

Add a new service ingester when:

- **Schema coverage:** The AWS service has resources that map to existing graph node types (Principal, Resource, Permission, etc.) or introduces new node types approved in the product roadmap.
- **Value to threat model:** Resources from the service are relevant to cloud security analysis (IAM, network, access control, compute, storage).
- **API stability:** The AWS service API is GA and stable (not in preview).

Examples of good candidates:
- **S3** — Resource nodes for buckets, bucket policies → Contains/CanAccess edges
- **KMS** — Resource nodes for keys, key policies → CanAccess edges
- **STS** — Minimal: ServicePrincipal nodes only, no edges (federated trust analysis)

Non-candidates:
- Preview or deprecated services
- Services with no permission or access semantics (e.g., CloudWatch alarms as bare resources)

## Architecture Overview

Every service ingester follows a three-file pattern:

```
go/internal/ingest/aws/<service>/
├── <service>_fetcher.go     — AWS API calls + pagination
├── <service>_transformer.go — Transform AWS types → ResourceSpec + EdgeSpec
└── <service>_ingester.go    — Implement Ingester interface
```

**Data flow:**
```
AWS API (fetcher)
  → AWS SDK types (raw)
  → Transformer (pure functions)
  → ResourceSpec + EdgeSpec (graph model)
  → Ingester.Enumerate() (channel-based streaming)
  → Graph database insert
```

## Step 1: Create the Service Directory

```bash
mkdir -p go/internal/ingest/aws/<service>
```

Example: `go/internal/ingest/aws/kms/`

## Step 2: Define the Client Interface

Create a local interface for the AWS SDK client to enable unit testing with mocks.

**File:** `go/internal/ingest/aws/<service>/<service>_fetcher.go`

```go
package <service>

import (
	"context"
	"github.com/aws/aws-sdk-go-v2/service/<service>"
	"golang.org/x/sync/semaphore"
)

// ClientInterface abstracts the AWS SDK client for testability.
// Use mockery to generate mocks.
type ClientInterface interface {
	List<Resource>(ctx context.Context, params *<service>.List<Resource>Input, ...func(*<service>.Options)) (*<service>.List<Resource>Output, error)
	// ... other methods as needed
}

// Fetch<Resource>s retrieves all <Resource> from AWS.
// Implements pagination automatically via AWS SDK paginators.
func Fetch<Resource>s(ctx context.Context, client ClientInterface, sem *semaphore.Weighted) ([]<service>types.<Resource>, error) {
	if err := sem.Acquire(ctx, 1); err != nil {
		return nil, fmt.Errorf("semaphore acquire failed: %w", err)
	}
	defer sem.Release(1)

	var resources []<service>types.<Resource>
	paginator := <service>.NewList<Resource>sPaginator(client, &<service>.List<Resource>sInput{})

	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("List<Resource>s failed: %w", err)
		}
		resources = append(resources, page.<Resource>s...)
	}

	return resources, nil
}
```

**Key patterns:**
- Use a `ClientInterface` to allow mocking without modifying test code.
- Always acquire a semaphore slot before calling AWS to limit concurrency.
- Use the AWS SDK's built-in `Paginator` pattern to handle pagination automatically.
- Return errors wrapping the underlying AWS error with context.

**Reference implementation:** [`go/internal/ingest/aws/iam/iam_fetcher.go`](../go/internal/ingest/aws/iam/iam_fetcher.go)

## Step 3: Implement the Transformer

Transform AWS SDK types into `ResourceSpec` and `EdgeSpec` graph model objects.

**File:** `go/internal/ingest/aws/<service>/<service>_transformer.go`

```go
package <service>

import (
	"fmt"
	"github.com/activable-cloud/activable.cloud/go/internal/ingest"
	"github.com/aws/aws-sdk-go-v2/service/<service>/types"
)

// <Resource>ToResourceSpec converts an AWS <Resource> to a graph ResourceSpec.
// All logic is pure (no I/O); unit tests do not require mocks.
func <Resource>ToResourceSpec(resource types.<Resource>, accountID string) ingest.ResourceSpec {
	arn := *resource.Arn // or construct from components
	spec := ingest.ResourceSpec{
		Label: "<ResourceType>",                    // e.g., "KmsKey"
		ID:    arn,
		Properties: map[string]interface{}{
			"account_id": accountID,
			"region":     resource.Region,         // if present
			"created_at": resource.CreateDate,
			// ... other properties
		},
		Edges: []ingest.EdgeSpec{},
	}
	return spec
}

// <Resource>PolicyToEdgeSpec constructs an edge representing a policy attachment.
// Example: KMS key policy grant.
func <Resource>PolicyToEdgeSpec(resourceARN, principalARN string) ingest.EdgeSpec {
	return ingest.EdgeSpec{
		FromID:   principalARN,
		ToID:     resourceARN,
		EdgeType: "CanAccess",                 // or appropriate edge type
		Properties: map[string]interface{}{
			"attachment_type": "resource_policy",
		},
	}
}
```

**Key patterns:**
- All transformer functions are **pure** — no AWS API calls, no I/O.
- Construct ARNs carefully (validate format per `activable-schema` canonicalizer if needed).
- Populate edge lists on the ResourceSpec itself; the ingester will emit them together.
- Use descriptive node labels (e.g., `"KmsKey"` not `"Key"`).
- Store timestamps in RFC3339 format for consistency.

**Reference implementation:** [`go/internal/ingest/aws/iam/iam_transformer.go`](../go/internal/ingest/aws/iam/iam_transformer.go)

## Step 4: Implement the Ingester Interface

Implement the `Ingester` interface to wire everything together.

**File:** `go/internal/ingest/aws/<service>/<service>_ingester.go`

```go
package <service>

import (
	"context"
	"fmt"
	"github.com/activable-cloud/activable.cloud/go/internal/ingest"
	"github.com/aws/aws-sdk-go-v2/service/<service>"
	"golang.org/x/sync/semaphore"
)

const MaxConcurrentCalls = 3  // Tune per service API rate limits

type <Service>Ingester struct {
	client    *<service>.Client
	accountID string
	semaphore *semaphore.Weighted
}

// New<Service>Ingester creates a new <service> ingester.
func New<Service>Ingester(client *<service>.Client, accountID string) *<Service>Ingester {
	return &<Service>Ingester{
		client:    client,
		accountID: accountID,
		semaphore: semaphore.NewWeighted(MaxConcurrentCalls),
	}
}

// Service returns the service name.
func (i *<Service>Ingester) Service() string {
	return "<service>"  // e.g., "kms"
}

// RequiredIAMActions returns the minimum IAM actions needed to enumerate this service.
// Used for generating least-privilege policies.
func (i *<Service>Ingester) RequiredIAMActions() []string {
	return []string{
		"<service>:List<Resource>s",
		"<service>:Describe<Resource>",
		"<service>:Get<Resource>Policy",
		// ... others as needed
	}
}

// Enumerate fetches all resources from the service and emits them as ResourceSpec items.
// Streams results via channels to support concurrent processing.
func (i *<Service>Ingester) Enumerate(ctx context.Context, region string) (<-chan ingest.ResourceSpec, <-chan error) {
	resourcesChan := make(chan ingest.ResourceSpec, 100)
	errorsChan := make(chan error, 10)

	go func() {
		defer close(resourcesChan)
		defer close(errorsChan)

		// Fetch <resource>s
		resources, err := Fetch<Resource>s(ctx, i.client, i.semaphore)
		if err != nil {
			errorsChan <- fmt.Errorf("failed to fetch <resource>s: %w", err)
			return
		}

		for _, resource := range resources {
			spec := <Resource>ToResourceSpec(resource, i.accountID)
			resourcesChan <- spec

			// Fetch related policy (if applicable)
			policy, err := Fetch<Resource>Policy(ctx, i.client, i.semaphore, *resource.Name)
			if err != nil {
				errorsChan <- fmt.Errorf("failed to fetch policy for %s: %w", *resource.Name, err)
				continue
			}

			// Parse policy and create edges
			// ... (see phase 5 IAM ingester for policy parsing pattern)
		}
	}()

	return resourcesChan, errorsChan
}
```

**Key patterns:**
- Implement three methods: `Service()`, `RequiredIAMActions()`, `Enumerate()`.
- `Enumerate()` must stream results via channels (not return a slice) to support concurrent processing.
- Close both channels when done to signal completion.
- Send errors to the error channel but continue processing remaining resources.
- Use bounded channel buffers (100 for resources, 10 for errors) to avoid goroutine leaks.

**Reference implementation:** [`go/internal/ingest/aws/iam/iam_ingester.go`](../go/internal/ingest/aws/iam/iam_ingester.go)

## Step 5: Register the Ingester

Wire the new ingester into the runtime.

**File:** `go/internal/ingest/register.go` (modify existing)

Add to the `NewRuntime()` function or equivalent:

```go
func NewRuntime(cfg *config.Config) (*Runtime, error) {
	// ... existing code ...

	// AWS Service ingesters
	iamIngester := iam.NewIAMIngester(iamClient, accountID)
	runtime.Ingesters["iam"] = iamIngester

	// NEW: Add your service
	<service>Client := <service>.NewFromConfig(cfg.AWSConfig)
	<service>Ingester := <service>.New<Service>Ingester(<service>Client, accountID)
	runtime.Ingesters["<service>"] = <service>Ingester

	return runtime, nil
}
```

## Step 6: Write Tests

### Unit Test the Transformer

Pure functions → pure tests. No mocks, no AWS calls.

**File:** `go/internal/ingest/aws/<service>/<service>_transformer_test.go`

```go
package <service>

import (
	"testing"
	"time"
	"github.com/aws/aws-sdk-go-v2/service/<service>/types"
	"github.com/stretchr/testify/assert"
)

func Test<Resource>ToResourceSpec(t *testing.T) {
	now := time.Now().UTC()
	resource := &types.<Resource>{
		Arn:        aws.String("arn:aws:<service>:us-east-1:123456789012:resource/my-resource"),
		Name:       aws.String("my-resource"),
		CreateDate: aws.Time(now),
		// ... populate other fields
	}

	spec := <Resource>ToResourceSpec(*resource, "123456789012")

	assert.Equal(t, "<ResourceType>", spec.Label)
	assert.Equal(t, "arn:aws:<service>:us-east-1:123456789012:resource/my-resource", spec.ID)
	assert.Equal(t, "123456789012", spec.Properties["account_id"])
	assert.Equal(t, 0, len(spec.Edges))  // or expected edge count
}

func Test<Resource>ToResourceSpec_PropertyCompleteness(t *testing.T) {
	// Verify that all non-nil fields are populated
	resource := &types.<Resource>{
		Arn:   aws.String("arn:aws:<service>:..."),
		// ... full fixture
	}

	spec := <Resource>ToResourceSpec(*resource, "123456789012")

	// Assert specific properties
	assert.NotEmpty(t, spec.Properties["created_at"])
	// ... check other critical fields
}
```

**Test coverage:** Aim for ≥98% branch coverage on the transformer. Every conditional must have at least one test.

### Mock the Fetcher

Use `mockery` to generate a mock `ClientInterface`.

```bash
cd go/internal/ingest/aws/<service>
mockery --name=ClientInterface --outpkg=<service>test --output=./<service>test
```

**File:** `go/internal/ingest/aws/<service>/<service>_fetcher_test.go`

```go
package <service>

import (
	"context"
	"testing"
	"github.com/aws/aws-sdk-go-v2/service/<service>/types"
	"github.com/stretchr/testify/assert"
	"golang.org/x/sync/semaphore"
)

func TestFetch<Resource>s_Success(t *testing.T) {
	// Use mockery-generated mock
	mock := new(<service>test.MockClientInterface)
	sem := semaphore.NewWeighted(3)

	// Mock ListResourcesPaginator
	// ... set up mock to return fixture data

	resources, err := Fetch<Resource>s(context.Background(), mock, sem)

	assert.NoError(t, err)
	assert.Equal(t, 2, len(resources))
}

func TestFetch<Resource>s_APIError(t *testing.T) {
	mock := new(<service>test.MockClientInterface)
	sem := semaphore.NewWeighted(3)

	// Mock to return error
	// ...

	_, err := Fetch<Resource>s(context.Background(), mock, sem)

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "List<Resource>s failed")
}
```

## Step 7: Add Test Fixtures

Create fixture JSON files for integration testing.

**Directory:** `go/internal/ingest/aws/<service>/testdata/fixtures/aws/<service>/`

Example: `go/internal/ingest/aws/<service>/testdata/fixtures/aws/<service>/describe-<resource>s.json`

```json
{
  "Resources": [
    {
      "Arn": "arn:aws:<service>:us-east-1:123456789012:resource/fixture-resource-1",
      "Name": "fixture-resource-1",
      "CreatedDate": "2024-01-01T12:00:00Z",
      ...
    }
  ]
}
```

These fixtures are used by integration tests and CloudGoat test scenarios.

## Step 8: Update Documentation

Add the service to `docs/system-architecture.md` §Graph Schema or §Supported Services:

```markdown
| Service | Node Types | Edge Types |
|---------|-----------|-----------|
| <service> | <ResourceType> | CanAccess, ... |
```

## Step 9: Required IAM Policy

Document the minimum IAM policy needed to run this ingester.

Add to `docs/system-architecture.md` §Security Boundary:

```json
{
  "Service": "<service>",
  "Actions": [
    "<service>:List<Resource>s",
    "<service>:Describe<Resource>",
    "<service>:Get<Resource>Policy"
  ]
}
```

This is auto-generated from `RequiredIAMActions()` in CI, but document the intent here.

## Step 10: PR Checklist

Before opening a pull request, verify:

- [ ] **Package structure:** `go/internal/ingest/aws/<service>/` contains exactly three `.go` files: `_fetcher.go`, `_transformer.go`, `_ingester.go`.
- [ ] **Interface compliance:** `<Service>Ingester` implements `Ingester` interface with no compiler errors.
- [ ] **Fetcher tests:** Mock-based unit tests for fetch functions; ≥98% branch coverage.
- [ ] **Transformer tests:** Pure-function unit tests for all transformation functions; ≥98% branch coverage.
- [ ] **Semaphore usage:** All AWS API calls acquire semaphore before executing.
- [ ] **Error handling:** Errors are wrapped with context; no bare `return err`.
- [ ] **Channel discipline:** `Enumerate()` returns buffered channels that are properly closed.
- [ ] **Registration:** Ingester registered in `go/internal/ingest/register.go`.
- [ ] **IAM actions documented:** `RequiredIAMActions()` returns accurate list; documented in `docs/system-architecture.md`.
- [ ] **Fixtures added:** Test fixtures in `go/internal/ingest/aws/<service>/testdata/fixtures/aws/<service>/`.
- [ ] **No TODO/FIXME:** All production logic is complete (no stubs).
- [ ] **go test -race clean:** `go test -race ./go/internal/ingest/aws/<service>/...` passes with no race detector warnings.
- [ ] **go vet clean:** `go vet ./go/internal/ingest/aws/<service>/...` reports no issues.
- [ ] **Names follow conventions:** Use full English words (no abbreviations per CLAUDE.md §0.5).

---

**Next:** After merging, add a public-facing CLI subcommand under `go/cmd/activable/` to trigger this ingester (e.g., `activable ingest iam`).
