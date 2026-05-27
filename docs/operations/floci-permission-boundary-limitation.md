# Floci / community LocalStack — permission boundary not returned by `get-role`

**Date:** 2026-05-24
**Discovered during:** ingester-surface AND-mask live verification
**Status:** Known limitation; live verification deferred to the LocalStack v4.7 upgrade

## What we tried

The seed script attaches a permission boundary to `developer-role`:

```bash
aws iam put-role-permissions-boundary \
    --role-name developer-role \
    --permissions-boundary arn:aws:iam::000000000000:policy/developer-boundary
```

The call succeeds (HTTP 200). The boundary policy itself exists (visible via `aws iam list-policies`).

## What happened

`aws iam get-role --role-name developer-role` returns:

```json
{
  "Role": {
    "Path": "/",
    "RoleName": "developer-role",
    "RoleId": "AROA...",
    "Arn": "arn:aws:iam::000000000000:role/developer-role",
    "CreateDate": "...",
    "AssumeRolePolicyDocument": { ... },
    "MaxSessionDuration": 3600
  }
}
```

No `PermissionsBoundary` field. The ingester reads `role.permissions_boundary()` from the AWS SDK and gets `None`. Result: the AND-mask in `PermissionsEnricher` does not run because there is no boundary to intersect against.

`aws iam list-attached-role-policies` correctly returns the attached managed policy. The managed-policy path is fine.

## Why

Floci (the community LocalStack fork used in this test environment) does not echo the PermissionsBoundary back through the IAM service `get-role` / `list-roles` responses. The boundary is stored in Floci's internal state — but the API response is incomplete relative to real AWS IAM.

LocalStack v4.7 CE (verified PASS on OIDC + multi-account routing in the prior spike) is expected to handle PermissionsBoundary correctly. Confirm in the LocalStack-upgrade phase.

## Impact

- Unit-test coverage of the AND-mask is complete (three tests in `permissions.rs` cover boundary restricting + no-boundary union + Deny skipping).
- Live verification of AND-mask is **not possible on Floci**. Defer to the LocalStack-upgrade phase.
- All other ingester-surface additions verified on Floci:
  - Managed-policy attachments correctly produce `HasEffectivePermission` edges with `source = "managed"`.
  - Inline-policy permissions produce edges with `source = "inline"`.
  - Schema additions (`Bucket`, `KmsKey`, `Policy`, edge types) compile and load.
  - Cypher index migrations gracefully degrade with WARN (separate AGE issue documented in `age-index-limitations.md`).

## Decision

Ship the ingester-surface changes as-is. Re-verify AND-mask end-to-end after the test-environment swap to LocalStack v4.7 CE. If v4.7 also omits the field, escalate to LocalStack Pro or move boundary tests to a real-AWS sandbox.

## Verification command for the upgrade phase

```bash
# After LocalStack v4.7 is deployed:
aws iam put-role-permissions-boundary --role-name developer-role \
    --permissions-boundary arn:aws:iam::000000000000:policy/developer-boundary
aws iam get-role --role-name developer-role | grep -A 3 PermissionsBoundary
# Expected: "PermissionsBoundary": { "PermissionsBoundaryType": ..., "PermissionsBoundaryArn": ... }
```

If the field appears: re-deploy ingester, reset graph, re-ingest, assert `developer-role` HasEffectivePermission s3 subset narrows to `{s3:GetObject}` only (per the design doc §3 AND-mask order).
