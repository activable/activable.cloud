# Developer Guide: Adding a New AWS Service Ingester

This guide walks you through adding a new AWS service ingester to Activable. Follow this pattern to ingest resources from any AWS service into the knowledge graph.

## When to Add a New Service

Before implementing, verify that:

1. **Schema coverage.** The service's resources map cleanly to existing node types (Principal, Resource, Permission) or require only 1–2 new node types. If more than 3 new types are needed, defer to v2.
2. **Value to end users.** The service adds meaningful relationships to the graph (e.g., S3 buckets referenced by IAM policies, Lambda functions assumed by roles). Standalone resource inventory without relationships is out of scope for v1.
3. **API stability.** AWS service is in general availability (GA) — avoid public-preview services that may restructure their API.
4. **Role coverage.** The service can be enumerated read-only via IAM API actions (no credential escalation, no cross-account access required beyond `sts:AssumeRole`).

**Examples:**
- **Add in v1:** S3 (buckets → Resource nodes, policy statements → edges), Lambda (functions → Resource nodes, execution role → CanAssume edge).
- **Defer to v2:** ECS ServiceDiscovery (requires custom bridge graph for service↔task↔container relationships), Macie (complex ML outputs that don't model as graph primitives).

## Directory Structure

Create a new package under `go/internal/ingest/aws/<service>/`:

```
go/internal/ingest/aws/<service>/
├── <service>_fetcher.go         # AWS SDK client interface + fetch methods
├── <service>_transformer.go     # Transform AWS SDK types → ResourceSpec
├── <service>_transformer_test.go # Unit tests for transformer (98%+ branch coverage)
├── <service>_ingester.go        # Ingester interface implementation
├── client.go                     # (Optional) Mock interface for testing
└── testdata/
    └── fixtures/aws/<service>/
        └── sample_response.json  # Real AWS API response for test fixtures
```

Use lowercase kebab-case for filenames and service names (e.g., `s3`, `ec2`, not `S3`, `EC2`).

## The Three Core Files

Every ingester has three files. Use the IAM ingester (`go/internal/ingest/aws/iam/`) as the canonical reference.

### 1. Fetcher (`<service>_fetcher.go`)

The fetcher encapsulates AWS SDK client setup and API calls. Define a `<Service>Client` interface that mirrors the AWS SDK:

```go
package s3

import (
    "context"
    "github.com/aws/aws-sdk-go-v2/service/s3"
    "github.com/aws/aws-sdk-go-v2/service/s3/types"
)

// S3Client defines the interface for S3 API calls used by the ingester.
// This allows mocking in tests.
type S3Client interface {
    ListBuckets(ctx context.Context, params *s3.ListBucketsInput, optFns ...func(*s3.Options)) (*s3.ListBucketsOutput, error)
    GetBucketPolicy(ctx context.Context, params *s3.GetBucketPolicyInput, optFns ...func(*s3.Options)) (*s3.GetBucketPolicyOutput, error)
    GetBucketAcl(ctx context.Context, params *s3.GetBucketAclInput, optFns ...func(*s3.Options)) (*s3.GetBucketAclOutput, error)
}

// FetchS3Buckets enumerates all S3 buckets in the account.
func FetchS3Buckets(ctx context.Context, client S3Client) ([]types.Bucket, error) {
    resp, err := client.ListBuckets(ctx, &s3.ListBucketsInput{})
    if err != nil {
        return nil, fmt.Errorf("ListBuckets: %w", err)
    }
    return resp.Buckets, nil
}

// FetchS3BucketPolicy fetches the bucket policy for a given bucket.
func FetchS3BucketPolicy(ctx context.Context, client S3Client, bucketName string) (string, error) {
    resp, err := client.GetBucketPolicy(ctx, &s3.GetBucketPolicyInput{
        Bucket: aws.String(bucketName),
    })
    if err != nil {
        // Ignore NoSuchBucketPolicy error — not all buckets have policies
        return "", nil
    }
    return aws.ToString(resp.Policy), nil
}
```

**Pattern:**
- Define a client interface matching the AWS SDK types you use.
- Write pure fetcher functions that take `context` + client interface.
- Return the raw AWS SDK types (not transformed).
- Use pagination paginators for large result sets (`ListBucketsPaginator`).
- Handle "not found" errors gracefully (log a warning, continue enumeration).

### 2. Transformer (`<service>_transformer.go` + `_transformer_test.go`)

The transformer converts AWS SDK types to `ingest.ResourceSpec` structs. Keep transformers pure functions with no I/O.

```go
package s3

import (
    "fmt"
    "github.com/aws/aws-sdk-go-v2/service/s3/types"
    "github.com/activable-cloud/activable.cloud/go/internal/ingest"
)

// BucketToResourceSpec converts an S3 bucket to a ResourceSpec node.
func BucketToResourceSpec(bucket types.Bucket, accountID string) ingest.ResourceSpec {
    bucketName := *bucket.Name
    arnStr := fmt.Sprintf("arn:aws:s3:::%s", bucketName)

    return ingest.ResourceSpec{
        Label: "Resource",
        ID:    arnStr,
        Properties: map[string]interface{}{
            "type":             "S3Bucket",
            "name":             bucketName,
            "creation_date":    bucket.CreationDate.Unix(),
            "aws_region":       "us-east-1", // S3 buckets are global
        },
        Edges: []ingest.EdgeSpec{}, // Edges added separately after full enumeration
    }
}

// BucketPolicyStatementToEdge converts an S3 bucket policy statement to a CanAccess edge.
// Returns (nil, nil) if the statement is a Deny (we skip those for v1).
func BucketPolicyStatementToEdge(
    bucketArn string,
    policyJSON string,
) []ingest.EdgeSpec {
    // Parse policyJSON, extract principals, actions, resources
    // Create CanAccess edges from each principal → bucketArn
    // Return the edges
    // (Implementation: same pattern as IAM transformer)
}
```

**Test pattern (98%+ branch coverage required):**

```go
package s3

import (
    "testing"
    "github.com/aws/aws-sdk-go-v2/service/s3/types"
    "github.com/activable-cloud/activable.cloud/go/internal/ingest"
)

func TestBucketToResourceSpec(t *testing.T) {
    bucket := types.Bucket{
        Name: aws.String("my-bucket"),
        CreationDate: aws.Time(time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)),
    }

    spec := BucketToResourceSpec(bucket, "123456789012")

    if spec.Label != "Resource" {
        t.Errorf("expected Label=Resource, got %q", spec.Label)
    }
    if spec.ID != "arn:aws:s3:::my-bucket" {
        t.Errorf("expected ID=arn:aws:s3:::my-bucket, got %q", spec.ID)
    }
    if spec.Properties["type"] != "S3Bucket" {
        t.Errorf("expected type=S3Bucket, got %v", spec.Properties["type"])
    }
}

func TestBucketPolicyStatementToEdge_Deny(t *testing.T) {
    // Test that Deny statements are skipped
}

func TestBucketPolicyStatementToEdge_UploadToAnyPrincipal(t *testing.T) {
    // Test parsing a statement granting s3:PutObject to a principal
}
```

**Pattern:**
- One test per transformation function.
- Use realistic AWS API response fixtures from `testdata/fixtures/aws/<service>/sample_response.json`.
- Test edge cases: empty results, missing optional fields, multiple principals per statement.
- Verify that ARN canonicalization follows `go/internal/ingest/aws/arn/canonicalize.go` rules.

### 3. Ingester Interface (`<service>_ingester.go`)

Implement the `ingest.Ingester` interface. This is the entry point for the runtime.

```go
package s3

import (
    "context"
    "fmt"
    "github.com/aws/aws-sdk-go-v2/service/s3"
    ingest "github.com/activable-cloud/activable.cloud/go/internal/ingest"
)

// S3Ingester implements the ingest.Ingester interface for S3.
type S3Ingester struct {
    client    S3Client
    accountID string
}

// NewS3Ingester creates a new S3 ingester.
func NewS3Ingester(client S3Client, accountID string) *S3Ingester {
    return &S3Ingester{
        client:    client,
        accountID: accountID,
    }
}

// Service returns the service name.
func (i *S3Ingester) Service() string {
    return "s3"
}

// RequiredIAMActions returns the minimum IAM policy needed for this ingester.
// Update docs/system-architecture.md §Security Boundary with this list.
func (i *S3Ingester) RequiredIAMActions() []string {
    return []string{
        "s3:ListAllMyBuckets",
        "s3:GetBucketPolicy",
        "s3:GetBucketAcl",
        "s3:GetBucketVersioning",
    }
}

// Enumerate enumerates S3 buckets and returns them via channels.
func (i *S3Ingester) Enumerate(ctx context.Context) (<-chan ingest.ResourceSpec, <-chan error) {
    resourcesChan := make(chan ingest.ResourceSpec, 100)
    errorsChan := make(chan error, 10)

    go func() {
        defer close(resourcesChan)
        defer close(errorsChan)

        // Fetch all buckets
        buckets, err := FetchS3Buckets(ctx, i.client)
        if err != nil {
            errorsChan <- fmt.Errorf("fetch buckets: %w", err)
            return
        }

        // Transform each bucket
        for _, bucket := range buckets {
            spec := BucketToResourceSpec(bucket, i.accountID)
            select {
            case resourcesChan <- spec:
            case <-ctx.Done():
                return
            }

            // Fetch and transform bucket policy
            policy, err := FetchS3BucketPolicy(ctx, i.client, *bucket.Name)
            if err != nil {
                fmt.Printf("warning: failed to fetch policy for bucket %s: %v\n", *bucket.Name, err)
                continue
            }

            edges := BucketPolicyStatementToEdge(spec.ID, policy)
            for _, edge := range edges {
                edgeSpec := ingest.ResourceSpec{
                    Label:      "Edge",
                    ID:         edge.ID,
                    Properties: edge.Properties,
                }
                select {
                case resourcesChan <- edgeSpec:
                case <-ctx.Done():
                    return
                }
            }
        }
    }()

    return resourcesChan, errorsChan
}
```

**Pattern:**
- `Service()` returns a lowercase string matching the directory name.
- `RequiredIAMActions()` lists the exact IAM actions used by `Enumerate()`. This list goes into the security-boundary section of `docs/system-architecture.md`.
- `Enumerate()` returns two channels: `resourcesChan` for nodes/edges and `errorsChan` for errors. Errors should be wrapped with context using `fmt.Errorf`.
- Use goroutines for concurrent enumeration if the API supports pagination (use semaphore pattern from IAM ingester for rate-limiting).
- Always check `ctx.Done()` before sending to channels; respect cancellation.

## Testing Ingesters

### Unit Tests (Transformer)

Write pure-function tests for the transformer. No mocks needed — just AWS SDK types as input.

```bash
cd go/internal/ingest/aws/s3
go test -v -cover ./...
```

Aim for **≥98% branch coverage**. Use `go tool cover -html=coverage.out` to visualize gaps.

### Integration Tests (Ingester Interface)

For the ingester itself, use mockery to generate mocks of the `<Service>Client` interface:

```bash
mockery --name=S3Client --output=mocks --outpkg=s3
```

Then write integration tests:

```go
package s3

import (
    "context"
    "testing"
    "github.com/stretchr/testify/assert"
    "github.com/stretchr/testify/mock"
)

func TestS3Ingester_Enumerate(t *testing.T) {
    mockClient := new(mocks.S3Client)
    mockClient.On("ListBuckets", mock.Anything, mock.Anything, mock.Anything).
        Return(&s3.ListBucketsOutput{
            Buckets: []types.Bucket{
                {Name: aws.String("test-bucket")},
            },
        }, nil)

    ingester := NewS3Ingester(mockClient, "123456789012")
    resources, errors := ingester.Enumerate(context.Background())

    for resource := range resources {
        assert.Equal(t, "Resource", resource.Label)
    }
    for err := range errors {
        assert.NoError(t, err)
    }
}
```

## Registering the Ingester

Add your ingester to the runtime in `go/internal/ingest/runtime.go`:

```go
// In runtime.go RegisterAll():

// Register S3 ingester
s3Client := s3.NewFromConfig(cfg)
s3Ingester := s3pkg.NewS3Ingester(s3Client, accountID)
r.ingesters = append(r.ingesters, s3Ingester)
```

## Updating Required IAM Actions

Document the minimum IAM policy in `docs/system-architecture.md` under the "Security Boundary" section:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "s3:ListAllMyBuckets",
        "s3:GetBucketPolicy",
        "s3:GetBucketAcl"
      ],
      "Resource": "*"
    }
  ]
}
```

Copy the exact list from `RequiredIAMActions()` in your ingester.

## PR Checklist

Before opening a pull request, verify:

- [ ] **Interface implemented.** `Ingester` interface methods all implemented (Service, RequiredIAMActions, Enumerate).
- [ ] **Fetcher tested with mocks.** AWS SDK client interface mocked; fetch functions tested.
- [ ] **Transformer at ≥98% branch coverage.** Run `go tool cover -html=coverage.out` and verify all branches exercised.
- [ ] **Fixture added.** Real AWS API response saved under `testdata/fixtures/aws/<service>/sample_response.json`.
- [ ] **Registered in Runtime.** Ingester added to `runtime.go` and wired into CLI.
- [ ] **Tests pass.** `go test -race ./...` clean, no data races.
- [ ] **Linting passes.** `golangci-lint run ./...` and `go vet ./...` clean.
- [ ] **Documentation updated.** `RequiredIAMActions()` list copied to `docs/system-architecture.md` Security Boundary section.
- [ ] **No plan-taxonomy tokens.** Commit messages and code comments contain no phase numbers, finding codes, or slice identifiers.
