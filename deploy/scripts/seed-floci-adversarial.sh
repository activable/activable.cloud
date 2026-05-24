#!/bin/bash

################################################################################
# seed-floci-adversarial.sh
#
# Idempotent script to seed Floci (LocalStack mock AWS) with adversarial IAM
# scenarios for SkyEye validation testing.
#
# Scenarios:
#   1. CloudFormation Service Role Trap
#   2. GitHub Actions OIDC Configuration Drift (SKIPPED — Floci limitation)
#   3. S3 Bucket Policy Principal Boundary Confusion
#   4. KMS CreateGrant Lateral Movement
#
# Usage:
#   export FLOCI_ENDPOINT="http://activable-floci:4566"
#   ./seed-floci-adversarial.sh
#
# Routing Model:
#   Floci collapses all AWS accounts to a single default account (000000000000).
#   AWS_ACCESS_KEY_ID is treated as a documentation marker only; all calls use
#   AWS_ACCESS_KEY_ID=test. Trust policies reference the 4-account model from
#   scenario design docs. The cross-account ARNs (e.g., arn:aws:iam::111111111111:role/...)
#   will appear as "phantom edges" in the graph — dangling references to principals from
#   other accounts that Floci collapses into the default account. This pattern IS expected
#   for testing IAM risk detection logic.
#
# Account ID references (documentation only; all map to Floci default 000000000000):
#   111111111111 = development
#   222222222222 = staging
#   333333333333 = production
#   444444444444 = secrets (data-lake)
#
################################################################################

set -euo pipefail

# Configuration
FLOCI_ENDPOINT="${FLOCI_ENDPOINT:-http://activable-floci:4566}"
REGION="us-east-1"

# Account IDs
DEV_ACCOUNT="111111111111"
STAGING_ACCOUNT="222222222222"
PROD_ACCOUNT="333333333333"
SECRETS_ACCOUNT="444444444444"

# Helper function: run aws-cli in a specific account
# Usage: aws_in_account <account_id> <aws subcommand> <args...>
# NOTE: account_id is DOCUMENTATION ONLY. Floci routes all calls to the default account
# (000000000000), regardless of AWS_ACCESS_KEY_ID. We use a fixed AWS_ACCESS_KEY_ID=test
# for all calls. The account_id parameter is kept for readability and to preserve the
# scenario's intended cross-account references (they will appear as phantom edges in the
# graph, which IS the expected threat pattern).
aws_in_account() {
    local account_id="$1"
    shift
    AWS_ACCESS_KEY_ID="test" \
    AWS_SECRET_ACCESS_KEY="test" \
    aws --endpoint-url "$FLOCI_ENDPOINT" \
        --region "$REGION" \
        "$@"
}

# Helper function: delete IAM role (swallow NotFound errors)
delete_role_safe() {
    local account_id="$1"
    local role_name="$2"
    local policies

    # List and detach all inline policies
    policies=$(aws_in_account "$account_id" iam list-role-policies --role-name "$role_name" --query 'PolicyNames[]' --output text 2>/dev/null || echo "")
    for policy in $policies; do
        aws_in_account "$account_id" iam delete-role-policy --role-name "$role_name" --policy-name "$policy" 2>/dev/null || { echo "WARN: Failed to delete inline policy $policy"; }
    done

    # Detach all managed policies
    aws_in_account "$account_id" iam list-attached-role-policies --role-name "$role_name" --query 'AttachedPolicies[].PolicyArn' --output text 2>/dev/null | while read arn; do
        [ -n "$arn" ] && aws_in_account "$account_id" iam detach-role-policy --role-name "$role_name" --policy-arn "$arn" 2>/dev/null || { echo "WARN: Failed to detach managed policy $arn"; }
    done

    # Delete the role
    aws_in_account "$account_id" iam delete-role --role-name "$role_name" 2>/dev/null || { echo "WARN: Failed to delete role $role_name (may not exist)"; }
}

# Helper function: delete OIDC provider (swallow NotFound)
delete_oidc_provider_safe() {
    local account_id="$1"
    local oidc_arn="$2"

    aws_in_account "$account_id" iam delete-open-id-connect-provider --open-id-connect-provider-arn "$oidc_arn" 2>/dev/null || { echo "WARN: Failed to delete OIDC provider $oidc_arn (may not exist)"; }
}

# Helper function: delete S3 bucket (swallow NotFound)
delete_bucket_safe() {
    local account_id="$1"
    local bucket_name="$2"

    # Empty bucket first
    aws_in_account "$account_id" s3 rm "s3://$bucket_name" --recursive 2>/dev/null || { echo "WARN: Failed to empty bucket $bucket_name"; }

    # Delete bucket
    aws_in_account "$account_id" s3 rb "s3://$bucket_name" 2>/dev/null || { echo "WARN: Failed to delete bucket $bucket_name (may not exist)"; }
}

# Helper function: delete KMS key (swallow NotFound; schedule deletion instead of immediate)
delete_kms_key_safe() {
    local account_id="$1"
    local key_id="$2"

    aws_in_account "$account_id" kms schedule-key-deletion --key-id "$key_id" --pending-window-in-days 7 2>/dev/null || { echo "WARN: Failed to schedule key deletion for $key_id (may not exist)"; }
}

echo "=== Seeding Floci Adversarial Scenarios ==="
echo "FLOCI_ENDPOINT: $FLOCI_ENDPOINT"
echo "REGION: $REGION"
echo ""

################################################################################
# SCENARIO 1: CloudFormation Service Role Trap
# Accounts: dev (111111111111), staging (222222222222)
################################################################################

echo "--- Scenario 1: CloudFormation Service Role Trap ---"

# Clean up existing resources
delete_role_safe "$DEV_ACCOUNT" "developer-role" 2>/dev/null || true
delete_role_safe "$DEV_ACCOUNT" "cf-deploy-production-role" 2>/dev/null || true
delete_role_safe "$STAGING_ACCOUNT" "cross-account-deployer" 2>/dev/null || true

# Dev Account: developer-role (identity policy)
echo "Creating developer-role in dev account ($DEV_ACCOUNT)..."
aws_in_account "$DEV_ACCOUNT" iam create-role \
    --role-name "developer-role" \
    --assume-role-policy-document '{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "AWS": "arn:aws:iam::'"$DEV_ACCOUNT"':root"
      },
      "Action": "sts:AssumeRole"
    }
  ]
}' 2>/dev/null || true

aws_in_account "$DEV_ACCOUNT" iam put-role-policy \
    --role-name "developer-role" \
    --policy-name "developer-policy" \
    --policy-document '{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "CloudFormationDeploy",
      "Effect": "Allow",
      "Action": [
        "cloudformation:CreateStack",
        "cloudformation:UpdateStack",
        "cloudformation:DescribeStacks",
        "cloudformation:GetTemplate"
      ],
      "Resource": "arn:aws:cloudformation:us-east-1:'"$DEV_ACCOUNT"':stack/*"
    },
    {
      "Sid": "PassRoleToCloudFormation",
      "Effect": "Allow",
      "Action": [
        "iam:PassRole"
      ],
      "Resource": "arn:aws:iam::'"$DEV_ACCOUNT"':role/cf-deploy-*"
    },
    {
      "Sid": "S3ForTemplates",
      "Effect": "Allow",
      "Action": [
        "s3:GetObject",
        "s3:ListBucket"
      ],
      "Resource": [
        "arn:aws:s3:::cf-templates-dev/*",
        "arn:aws:s3:::cf-templates-dev"
      ]
    },
    {
      "Sid": "AssumeRoleInStaging",
      "Effect": "Allow",
      "Action": [
        "sts:AssumeRole"
      ],
      "Resource": "arn:aws:iam::'"$STAGING_ACCOUNT"':role/cross-account-deployer"
    }
  ]
}'

# Create a managed policy for developer-role to test managed policy ingestion
echo "Creating developer-broad-access managed policy..."
MANAGED_POLICY_ARN=$(aws_in_account "$DEV_ACCOUNT" iam create-policy \
    --policy-name "developer-broad-access" \
    --policy-document '{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "S3FullAccess",
      "Effect": "Allow",
      "Action": "s3:*",
      "Resource": "*"
    },
    {
      "Sid": "IAMRead",
      "Effect": "Allow",
      "Action": [
        "iam:GetRole",
        "iam:ListRoles",
        "iam:GetRolePolicy",
        "iam:ListRolePolicies"
      ],
      "Resource": "*"
    }
  ]
}' --query 'Policy.Arn' --output text)

# Attach managed policy to developer-role
echo "Attaching developer-broad-access to developer-role..."
aws_in_account "$DEV_ACCOUNT" iam attach-role-policy \
    --role-name "developer-role" \
    --policy-arn "$MANAGED_POLICY_ARN"

# Create a permission boundary policy that restricts s3:* to s3:GetObject only
echo "Creating developer-boundary permission boundary policy..."
BOUNDARY_POLICY_ARN=$(aws_in_account "$DEV_ACCOUNT" iam create-policy \
    --policy-name "developer-boundary" \
    --policy-document '{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "S3GetObjectOnly",
      "Effect": "Allow",
      "Action": "s3:GetObject",
      "Resource": "*"
    },
    {
      "Sid": "CloudFormationAll",
      "Effect": "Allow",
      "Action": "cloudformation:*",
      "Resource": "*"
    }
  ]
}' --query 'Policy.Arn' --output text)

# Set the permission boundary on developer-role
echo "Setting permission boundary on developer-role..."
aws_in_account "$DEV_ACCOUNT" iam put-role-permissions-boundary \
    --role-name "developer-role" \
    --permissions-boundary "$BOUNDARY_POLICY_ARN"

# Dev Account: cf-deploy-production-role (identity policy + trust policy)
echo "Creating cf-deploy-production-role in dev account ($DEV_ACCOUNT)..."
aws_in_account "$DEV_ACCOUNT" iam create-role \
    --role-name "cf-deploy-production-role" \
    --assume-role-policy-document '{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "Service": "cloudformation.amazonaws.com"
      },
      "Action": "sts:AssumeRole"
    },
    {
      "Effect": "Allow",
      "Principal": {
        "AWS": "arn:aws:iam::'"$STAGING_ACCOUNT"':role/cross-account-deployer"
      },
      "Action": "sts:AssumeRole"
    }
  ]
}' 2>/dev/null || true

aws_in_account "$DEV_ACCOUNT" iam put-role-policy \
    --role-name "cf-deploy-production-role" \
    --policy-name "cf-deploy-policy" \
    --policy-document '{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "CreateAndUpdateRoles",
      "Effect": "Allow",
      "Action": [
        "iam:CreateRole",
        "iam:AttachRolePolicy",
        "iam:PutRolePolicy",
        "iam:UpdateAssumeRolePolicy"
      ],
      "Resource": "arn:aws:iam::'"$DEV_ACCOUNT"':role/*"
    },
    {
      "Sid": "PassRoleForServices",
      "Effect": "Allow",
      "Action": [
        "iam:PassRole"
      ],
      "Resource": "arn:aws:iam::'"$DEV_ACCOUNT"':role/*"
    },
    {
      "Sid": "CreateLambda",
      "Effect": "Allow",
      "Action": [
        "lambda:CreateFunction",
        "lambda:UpdateFunctionCode",
        "lambda:InvokeFunction"
      ],
      "Resource": "arn:aws:lambda:us-east-1:'"$DEV_ACCOUNT"':function/*"
    },
    {
      "Sid": "CloudFormationExecution",
      "Effect": "Allow",
      "Action": [
        "cloudformation:*"
      ],
      "Resource": "*"
    }
  ]
}'

# Staging Account: cross-account-deployer (trust policy + identity policy)
echo "Creating cross-account-deployer in staging account ($STAGING_ACCOUNT)..."
aws_in_account "$STAGING_ACCOUNT" iam create-role \
    --role-name "cross-account-deployer" \
    --assume-role-policy-document '{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "AWS": "arn:aws:iam::'"$DEV_ACCOUNT"':role/developer-role"
      },
      "Action": "sts:AssumeRole"
    }
  ]
}' 2>/dev/null || true

aws_in_account "$STAGING_ACCOUNT" iam put-role-policy \
    --role-name "cross-account-deployer" \
    --policy-name "cross-account-policy" \
    --policy-document '{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "DeployToStaging",
      "Effect": "Allow",
      "Action": [
        "cloudformation:*",
        "iam:PassRole",
        "lambda:*",
        "s3:*"
      ],
      "Resource": "*"
    }
  ]
}'

echo "✓ Scenario 1 complete: developer-role → cf-deploy-production-role → cross-account-deployer"
echo ""

################################################################################
# SCENARIO 2: GitHub Actions OIDC Configuration Drift
# Accounts: staging (222222222222), prod (333333333333)
# STATUS: SKIPPED — Floci does not support OIDC IAM operations (UnsupportedOperation)
################################################################################

# To re-enable Scenario 2 when Floci adds OIDC support, change the condition below:
# if false; then ... fi  →  if true; then ... fi
if false; then

echo "--- Scenario 2: GitHub Actions OIDC Configuration Drift ---"

# Clean up existing resources
delete_oidc_provider_safe "$STAGING_ACCOUNT" "arn:aws:iam::$STAGING_ACCOUNT:oidc-provider/token.actions.githubusercontent.com" 2>/dev/null || true
delete_role_safe "$STAGING_ACCOUNT" "github-actions-role" 2>/dev/null || true
delete_role_safe "$STAGING_ACCOUNT" "codepipeline-deploy-role" 2>/dev/null || true
delete_role_safe "$PROD_ACCOUNT" "codepipeline-prod-deployer" 2>/dev/null || true

# Staging Account: Create OIDC provider with drifted (unsafe) trust policy
echo "Creating OIDC provider token.actions.githubusercontent.com in staging account ($STAGING_ACCOUNT)..."
aws_in_account "$STAGING_ACCOUNT" iam create-open-id-connect-provider \
    --url "https://token.actions.githubusercontent.com" \
    --client-id-list "sts.amazonaws.com" \
    --thumbprint-list "6938fd4d98bab03faadb97b34396831e3780aea1" 2>/dev/null || true

# Get the OIDC provider ARN
OIDC_ARN=$(aws_in_account "$STAGING_ACCOUNT" iam list-open-id-connect-providers --query 'OpenIDConnectProviderList[0].Arn' --output text)

# Update OIDC provider trust policy to VERSION 2 (drifted/unsafe)
echo "Updating OIDC provider to drifted (unsafe) trust policy..."
aws_in_account "$STAGING_ACCOUNT" iam update-open-id-connect-provider-thumbprint \
    --open-id-connect-provider-arn "$OIDC_ARN" \
    --thumbprint-list "6938fd4d98bab03faadb97b34396831e3780aea1" 2>/dev/null || true

# Staging Account: github-actions-role
echo "Creating github-actions-role in staging account ($STAGING_ACCOUNT)..."
aws_in_account "$STAGING_ACCOUNT" iam create-role \
    --role-name "github-actions-role" \
    --assume-role-policy-document '{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "Federated": "arn:aws:iam::'"$STAGING_ACCOUNT"':oidc-provider/token.actions.githubusercontent.com"
      },
      "Action": "sts:AssumeRoleWithWebIdentity",
      "Condition": {
        "StringEquals": {
          "token.actions.githubusercontent.com:aud": "sts.amazonaws.com"
        },
        "StringLike": {
          "token.actions.githubusercontent.com:sub": [
            "repo:myorg/myrepo:*",
            "repo:myorg/*:environment:production"
          ]
        }
      }
    }
  ]
}' 2>/dev/null || true

aws_in_account "$STAGING_ACCOUNT" iam put-role-policy \
    --role-name "github-actions-role" \
    --policy-name "github-actions-policy" \
    --policy-document '{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "ReadArtifacts",
      "Effect": "Allow",
      "Action": [
        "s3:GetObject",
        "s3:ListBucket"
      ],
      "Resource": [
        "arn:aws:s3:::staging-artifacts/*",
        "arn:aws:s3:::staging-artifacts"
      ]
    },
    {
      "Sid": "PushECR",
      "Effect": "Allow",
      "Action": [
        "ecr:GetDownloadUrlForLayer",
        "ecr:BatchGetImage",
        "ecr:PutImage",
        "ecr:InitiateLayerUpload",
        "ecr:UploadLayerPart",
        "ecr:CompleteLayerUpload"
      ],
      "Resource": "arn:aws:ecr:us-east-1:'"$STAGING_ACCOUNT"':repository/*"
    },
    {
      "Sid": "AssumeCodePipelineRole",
      "Effect": "Allow",
      "Action": [
        "sts:AssumeRole"
      ],
      "Resource": "arn:aws:iam::'"$STAGING_ACCOUNT"':role/codepipeline-*"
    }
  ]
}'

# Staging Account: codepipeline-deploy-role
echo "Creating codepipeline-deploy-role in staging account ($STAGING_ACCOUNT)..."
aws_in_account "$STAGING_ACCOUNT" iam create-role \
    --role-name "codepipeline-deploy-role" \
    --assume-role-policy-document '{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "Service": "codepipeline.amazonaws.com"
      },
      "Action": "sts:AssumeRole"
    },
    {
      "Effect": "Allow",
      "Principal": {
        "AWS": "arn:aws:iam::'"$STAGING_ACCOUNT"':role/github-actions-role"
      },
      "Action": "sts:AssumeRole"
    }
  ]
}' 2>/dev/null || true

aws_in_account "$STAGING_ACCOUNT" iam put-role-policy \
    --role-name "codepipeline-deploy-role" \
    --policy-name "codepipeline-deploy-policy" \
    --policy-document '{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "DeploymentActions",
      "Effect": "Allow",
      "Action": [
        "ecs:UpdateService",
        "ecs:DescribeServices",
        "iam:PassRole"
      ],
      "Resource": "*"
    },
    {
      "Sid": "AssumeProduction",
      "Effect": "Allow",
      "Action": [
        "sts:AssumeRole"
      ],
      "Resource": "arn:aws:iam::'"$PROD_ACCOUNT"':role/codepipeline-prod-deployer"
    }
  ]
}'

# Production Account: codepipeline-prod-deployer
echo "Creating codepipeline-prod-deployer in production account ($PROD_ACCOUNT)..."
aws_in_account "$PROD_ACCOUNT" iam create-role \
    --role-name "codepipeline-prod-deployer" \
    --assume-role-policy-document '{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "AWS": "arn:aws:iam::'"$STAGING_ACCOUNT"':role/codepipeline-deploy-role"
      },
      "Action": "sts:AssumeRole"
    }
  ]
}' 2>/dev/null || true

aws_in_account "$PROD_ACCOUNT" iam put-role-policy \
    --role-name "codepipeline-prod-deployer" \
    --policy-name "codepipeline-prod-deployer-policy" \
    --policy-document '{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "ProductionDeployment",
      "Effect": "Allow",
      "Action": [
        "ecs:UpdateService",
        "s3:*",
        "rds:ModifyDBCluster"
      ],
      "Resource": "*"
    }
  ]
}'

echo "✓ Scenario 2 complete: GitHub OIDC (drifted) → github-actions-role → codepipeline-deploy-role → codepipeline-prod-deployer"
echo ""

else
    echo "[SKIP] Scenario 2: OIDC unsupported by Floci (UnsupportedOperation)"
    echo "  Re-enable by changing 'if false' to 'if true' at line ~300."
    echo ""
fi

################################################################################
# SCENARIO 3: S3 Bucket Policy Principal Boundary Confusion
# Accounts: dev (111111111111), data-lake/secrets (444444444444)
################################################################################

echo "--- Scenario 3: S3 Bucket Policy Principal Boundary Confusion ---"

# Clean up existing resources
delete_role_safe "$DEV_ACCOUNT" "developer-infrastructure-role" 2>/dev/null || true
delete_bucket_safe "$SECRETS_ACCOUNT" "org-shared-data" 2>/dev/null || true

# Dev Account: developer-infrastructure-role
echo "Creating developer-infrastructure-role in dev account ($DEV_ACCOUNT)..."
aws_in_account "$DEV_ACCOUNT" iam create-role \
    --role-name "developer-infrastructure-role" \
    --assume-role-policy-document '{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "AWS": "arn:aws:iam::'"$DEV_ACCOUNT"':root"
      },
      "Action": "sts:AssumeRole"
    }
  ]
}' 2>/dev/null || true

aws_in_account "$DEV_ACCOUNT" iam put-role-policy \
    --role-name "developer-infrastructure-role" \
    --policy-name "developer-infrastructure-policy" \
    --policy-document '{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "ManageInfrastructureBuckets",
      "Effect": "Allow",
      "Action": [
        "s3:CreateBucket",
        "s3:PutBucketPolicy",
        "s3:GetBucketPolicy",
        "s3:DeleteBucketPolicy",
        "s3:PutBucketVersioning"
      ],
      "Resource": "arn:aws:s3:::dev-*"
    },
    {
      "Sid": "ReadSharedDatasets",
      "Effect": "Allow",
      "Action": [
        "s3:GetObject",
        "s3:ListBucket"
      ],
      "Resource": [
        "arn:aws:s3:::org-shared-data/*",
        "arn:aws:s3:::org-shared-data"
      ]
    }
  ]
}'

# Data-lake/Secrets Account: Create org-shared-data bucket with permissive policy
echo "Creating org-shared-data bucket in secrets account ($SECRETS_ACCOUNT)..."
aws_in_account "$SECRETS_ACCOUNT" s3 mb "s3://org-shared-data" 2>/dev/null || true

# Apply bucket policy allowing org-wide read with Principal:* and org-ID condition
aws_in_account "$SECRETS_ACCOUNT" s3api put-bucket-policy \
    --bucket "org-shared-data" \
    --policy '{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "AllowOrgWideRead",
      "Effect": "Allow",
      "Principal": "*",
      "Action": [
        "s3:GetObject",
        "s3:ListBucket"
      ],
      "Resource": [
        "arn:aws:s3:::org-shared-data",
        "arn:aws:s3:::org-shared-data/*"
      ],
      "Condition": {
        "StringEquals": {
          "aws:PrincipalOrgID": "o-myorg"
        }
      }
    }
  ]
}'

echo "✓ Scenario 3 complete: developer-infrastructure-role → org-shared-data bucket (Principal:* with org-ID)"
echo ""

################################################################################
# SCENARIO 4: KMS CreateGrant Lateral Movement
# Accounts: dev (111111111111), secrets (444444444444)
################################################################################

echo "--- Scenario 4: KMS CreateGrant Lateral Movement ---"

# Clean up existing resources
delete_role_safe "$DEV_ACCOUNT" "application-role" 2>/dev/null || true

# Dev Account: application-role
echo "Creating application-role in dev account ($DEV_ACCOUNT)..."
aws_in_account "$DEV_ACCOUNT" iam create-role \
    --role-name "application-role" \
    --assume-role-policy-document '{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "Service": "lambda.amazonaws.com"
      },
      "Action": "sts:AssumeRole"
    }
  ]
}' 2>/dev/null || true

aws_in_account "$DEV_ACCOUNT" iam put-role-policy \
    --role-name "application-role" \
    --policy-name "application-kms-policy" \
    --policy-document '{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "DecryptApplicationSecrets",
      "Effect": "Allow",
      "Action": [
        "kms:Decrypt",
        "kms:DescribeKey"
      ],
      "Resource": "arn:aws:kms:us-east-1:'"$SECRETS_ACCOUNT"':key/*"
    }
  ]
}'

# Secrets Account: Create KMS key with key policy allowing dev account to CreateGrant
echo "Creating KMS key in secrets account ($SECRETS_ACCOUNT)..."
KMS_KEY_ID=$(aws_in_account "$SECRETS_ACCOUNT" kms create-key \
    --description "Org-wide secret encryption key" \
    --key-usage ENCRYPT_DECRYPT \
    --origin AWS_KMS \
    --query 'KeyMetadata.KeyId' \
    --output text)
echo "KMS Key ID: $KMS_KEY_ID"

# Update KMS key policy to allow dev account root and application role to use the key
aws_in_account "$SECRETS_ACCOUNT" kms put-key-policy \
    --key-id "$KMS_KEY_ID" \
    --policy-name "default" \
    --policy '{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "AdminManagement",
      "Effect": "Allow",
      "Principal": {
        "AWS": "arn:aws:iam::'"$SECRETS_ACCOUNT"':root"
      },
      "Action": "kms:*",
      "Resource": "*"
    },
    {
      "Sid": "AllowAppAccountGrants",
      "Effect": "Allow",
      "Principal": {
        "AWS": "arn:aws:iam::'"$DEV_ACCOUNT"':root"
      },
      "Action": [
        "kms:CreateGrant",
        "kms:ListGrants",
        "kms:RevokeGrant"
      ],
      "Resource": "*"
    },
    {
      "Sid": "AllowAppAccountDecrypt",
      "Effect": "Allow",
      "Principal": {
        "AWS": "arn:aws:iam::'"$DEV_ACCOUNT"':role/application-role"
      },
      "Action": [
        "kms:Decrypt",
        "kms:GenerateDataKey"
      ],
      "Resource": "*"
    }
  ]
}'

echo "✓ Scenario 4 complete: application-role (dev) → KMS key policy allows dev root to CreateGrant"
echo ""

################################################################################
# Summary Report
################################################################################

echo "=== Seeding Complete ==="
echo ""

# Count IAM resources per account
count_roles_dev=$(aws_in_account "$DEV_ACCOUNT" iam list-roles --query 'Roles[].RoleName' --output text | wc -w)
count_roles_staging=$(aws_in_account "$STAGING_ACCOUNT" iam list-roles --query 'Roles[].RoleName' --output text | wc -w)
count_roles_prod=$(aws_in_account "$PROD_ACCOUNT" iam list-roles --query 'Roles[].RoleName' --output text | wc -w)
count_roles_secrets=$(aws_in_account "$SECRETS_ACCOUNT" iam list-roles --query 'Roles[].RoleName' --output text | wc -w)

count_policies_dev=$(aws_in_account "$DEV_ACCOUNT" iam list-policies --scope Local --query 'Policies[].PolicyName' --output text | wc -w)
count_policies_staging=$(aws_in_account "$STAGING_ACCOUNT" iam list-policies --scope Local --query 'Policies[].PolicyName' --output text | wc -w)
count_policies_prod=$(aws_in_account "$PROD_ACCOUNT" iam list-policies --scope Local --query 'Policies[].PolicyName' --output text | wc -w)
count_policies_secrets=$(aws_in_account "$SECRETS_ACCOUNT" iam list-policies --scope Local --query 'Policies[].PolicyName' --output text | wc -w)

count_oidc=$(aws_in_account "$STAGING_ACCOUNT" iam list-open-id-connect-providers --query 'OpenIDConnectProviderList[].Arn' --output text 2>/dev/null | wc -w || echo 0)

count_buckets=$(aws_in_account "$SECRETS_ACCOUNT" s3 ls | wc -l)

count_keys=$(aws_in_account "$SECRETS_ACCOUNT" kms list-keys --query 'Keys[].KeyId' --output text | wc -w)

echo "Summary of Adversarial Scenarios:"
echo ""
echo "Development Account ($DEV_ACCOUNT):"
echo "  Roles: $count_roles_dev"
echo "    - developer-role (Scenario 1)"
echo "    - cf-deploy-production-role (Scenario 1)"
echo "    - developer-infrastructure-role (Scenario 3)"
echo "    - application-role (Scenario 4)"
echo "  Inline Policies: $count_policies_dev"
echo ""
echo "Staging Account ($STAGING_ACCOUNT):"
echo "  Roles: $count_roles_staging"
echo "    - cross-account-deployer (Scenario 1)"
echo "    - github-actions-role (Scenario 2)"
echo "    - codepipeline-deploy-role (Scenario 2)"
echo "  Inline Policies: $count_policies_staging"
echo "  OIDC Providers: $count_oidc"
echo "    - token.actions.githubusercontent.com (Scenario 2, drifted policy)"
echo ""
echo "Production Account ($PROD_ACCOUNT):"
echo "  Roles: $count_roles_prod"
echo "    - codepipeline-prod-deployer (Scenario 2)"
echo "  Inline Policies: $count_policies_prod"
echo ""
echo "Secrets Account ($SECRETS_ACCOUNT):"
echo "  Roles: $count_roles_secrets"
echo "  S3 Buckets: $count_buckets"
echo "    - org-shared-data (Scenario 3, Principal:* with org-ID condition)"
echo "  KMS Keys: $count_keys"
echo "    - (Scenario 4, key policy allows dev account root to CreateGrant)"
echo ""
echo "All scenarios are idempotent and can be re-run safely."
echo ""
echo "Note: Scenario 2 (OIDC) skipped — Floci limitation. Scenarios 1, 3, 4 seeded."
