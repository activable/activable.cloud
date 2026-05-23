#!/usr/bin/env bash
# seed-adversarial-scenarios.sh — Seed Floci with 5 realistic privilege escalation scenarios
# Each scenario contains innocent-looking permissions that chain to escalation
# Run after floci health check passes

set -euo pipefail

export AWS_ENDPOINT_URL=${AWS_ENDPOINT_URL:-http://localhost:4566}
export AWS_ACCESS_KEY_ID=${AWS_ACCESS_KEY_ID:-test}
export AWS_SECRET_ACCESS_KEY=${AWS_SECRET_ACCESS_KEY:-test}
export AWS_DEFAULT_REGION=${AWS_DEFAULT_REGION:-us-east-1}

echo "=== Seeding Floci with Adversarial Scenarios ==="
echo "Endpoint: $AWS_ENDPOINT_URL"
echo "Region: $AWS_DEFAULT_REGION"
echo ""

# Temporary directory for policy documents
POLICY_DIR="/tmp/adversarial_policies"
mkdir -p "$POLICY_DIR"

# ============================================================================
# SCENARIO 1: CloudFormation Service Role Trap
# ============================================================================
echo "[Scenario 1] Seeding CloudFormation Service Role Trap..."

# developer-role identity policy
cat > "$POLICY_DIR/scenario1_developer_identity.json" << 'EOF'
{
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
      "Resource": "arn:aws:cloudformation:us-east-1:111111111111:stack/*"
    },
    {
      "Sid": "PassRoleToCloudFormation",
      "Effect": "Allow",
      "Action": ["iam:PassRole"],
      "Resource": "arn:aws:iam::111111111111:role/cf-deploy-*"
    },
    {
      "Sid": "S3ForTemplates",
      "Effect": "Allow",
      "Action": ["s3:GetObject", "s3:ListBucket"],
      "Resource": [
        "arn:aws:s3:::cf-templates-dev/*",
        "arn:aws:s3:::cf-templates-dev"
      ]
    },
    {
      "Sid": "AssumeRoleInStaging",
      "Effect": "Allow",
      "Action": ["sts:AssumeRole"],
      "Resource": "arn:aws:iam::222222222222:role/cross-account-deployer"
    }
  ]
}
EOF

# cf-deploy-production-role identity policy
cat > "$POLICY_DIR/scenario1_cf_deploy_identity.json" << 'EOF'
{
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
      "Resource": "arn:aws:iam::111111111111:role/*"
    },
    {
      "Sid": "PassRoleForServices",
      "Effect": "Allow",
      "Action": ["iam:PassRole"],
      "Resource": "arn:aws:iam::111111111111:role/*"
    },
    {
      "Sid": "CreateLambda",
      "Effect": "Allow",
      "Action": [
        "lambda:CreateFunction",
        "lambda:UpdateFunctionCode",
        "lambda:InvokeFunction"
      ],
      "Resource": "arn:aws:lambda:us-east-1:111111111111:function/*"
    },
    {
      "Sid": "CloudFormationExecution",
      "Effect": "Allow",
      "Action": ["cloudformation:*"],
      "Resource": "*"
    }
  ]
}
EOF

# cf-deploy-production-role trust policy
cat > "$POLICY_DIR/scenario1_cf_deploy_trust.json" << 'EOF'
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {"Service": "cloudformation.amazonaws.com"},
      "Action": "sts:AssumeRole"
    },
    {
      "Effect": "Allow",
      "Principal": {"AWS": "arn:aws:iam::222222222222:role/cross-account-deployer"},
      "Action": "sts:AssumeRole"
    }
  ]
}
EOF

# cross-account-deployer trust policy (in staging)
cat > "$POLICY_DIR/scenario1_cross_account_trust.json" << 'EOF'
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {"AWS": "arn:aws:iam::111111111111:role/developer-role"},
      "Action": "sts:AssumeRole"
    }
  ]
}
EOF

# cross-account-deployer identity policy (in staging)
cat > "$POLICY_DIR/scenario1_cross_account_identity.json" << 'EOF'
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "DeployToStaging",
      "Effect": "Allow",
      "Action": ["cloudformation:*", "iam:PassRole", "lambda:*", "s3:*"],
      "Resource": "*"
    }
  ]
}
EOF

# Create roles for Scenario 1
aws iam create-role \
  --role-name developer-role \
  --assume-role-policy-document '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"ec2.amazonaws.com"},"Action":"sts:AssumeRole"}]}' \
  --endpoint-url "$AWS_ENDPOINT_URL" 2>/dev/null || true

aws iam put-role-policy \
  --role-name developer-role \
  --policy-name developer-policy \
  --policy-document file://"$POLICY_DIR/scenario1_developer_identity.json" \
  --endpoint-url "$AWS_ENDPOINT_URL"

aws iam create-role \
  --role-name cf-deploy-production-role \
  --assume-role-policy-document file://"$POLICY_DIR/scenario1_cf_deploy_trust.json" \
  --endpoint-url "$AWS_ENDPOINT_URL" 2>/dev/null || true

aws iam put-role-policy \
  --role-name cf-deploy-production-role \
  --policy-name cf-deploy-policy \
  --policy-document file://"$POLICY_DIR/scenario1_cf_deploy_identity.json" \
  --endpoint-url "$AWS_ENDPOINT_URL"

# Create cross-account role (in staging)
aws iam create-role \
  --role-name cross-account-deployer \
  --assume-role-policy-document file://"$POLICY_DIR/scenario1_cross_account_trust.json" \
  --endpoint-url "$AWS_ENDPOINT_URL" 2>/dev/null || true

aws iam put-role-policy \
  --role-name cross-account-deployer \
  --policy-name cross-account-policy \
  --policy-document file://"$POLICY_DIR/scenario1_cross_account_identity.json" \
  --endpoint-url "$AWS_ENDPOINT_URL"

echo "✓ Scenario 1 roles and policies created"

# ============================================================================
# SCENARIO 2: GitHub Actions OIDC Configuration Drift
# ============================================================================
echo "[Scenario 2] Seeding GitHub Actions OIDC Drift..."

# OIDC provider trust policy (unsafe version with drift)
cat > "$POLICY_DIR/scenario2_oidc_trust.json" << 'EOF'
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {"Federated": "arn:aws:iam::222222222222:oidc-provider/token.actions.githubusercontent.com"},
      "Action": "sts:AssumeRoleWithWebIdentity",
      "Condition": {
        "StringEquals": {"token.actions.githubusercontent.com:aud": "sts.amazonaws.com"},
        "StringLike": {
          "token.actions.githubusercontent.com:sub": [
            "repo:myorg/myrepo:*",
            "repo:myorg/*:environment:production"
          ]
        }
      }
    }
  ]
}
EOF

# github-actions-role identity policy
cat > "$POLICY_DIR/scenario2_github_actions_identity.json" << 'EOF'
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "ReadArtifacts",
      "Effect": "Allow",
      "Action": ["s3:GetObject", "s3:ListBucket"],
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
      "Resource": "arn:aws:ecr:us-east-1:222222222222:repository/*"
    },
    {
      "Sid": "AssumeCodePipelineRole",
      "Effect": "Allow",
      "Action": ["sts:AssumeRole"],
      "Resource": "arn:aws:iam::222222222222:role/codepipeline-*"
    }
  ]
}
EOF

# codepipeline-deploy-role identity policy
cat > "$POLICY_DIR/scenario2_codepipeline_identity.json" << 'EOF'
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "DeploymentActions",
      "Effect": "Allow",
      "Action": ["ecs:UpdateService", "ecs:DescribeServices", "iam:PassRole"],
      "Resource": "*"
    },
    {
      "Sid": "AssumeProduction",
      "Effect": "Allow",
      "Action": ["sts:AssumeRole"],
      "Resource": "arn:aws:iam::333333333333:role/codepipeline-prod-deployer"
    }
  ]
}
EOF

# codepipeline-prod-deployer trust policy (in prod)
cat > "$POLICY_DIR/scenario2_codepipeline_prod_trust.json" << 'EOF'
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {"AWS": "arn:aws:iam::222222222222:role/codepipeline-deploy-role"},
      "Action": "sts:AssumeRole"
    }
  ]
}
EOF

# codepipeline-prod-deployer identity policy (in prod)
cat > "$POLICY_DIR/scenario2_codepipeline_prod_identity.json" << 'EOF'
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "ProductionDeployment",
      "Effect": "Allow",
      "Action": ["ecs:UpdateService", "s3:*", "rds:ModifyDBCluster"],
      "Resource": "*"
    }
  ]
}
EOF

# Create roles for Scenario 2
aws iam create-role \
  --role-name github-actions-role \
  --assume-role-policy-document file://"$POLICY_DIR/scenario2_oidc_trust.json" \
  --endpoint-url "$AWS_ENDPOINT_URL" 2>/dev/null || true

aws iam put-role-policy \
  --role-name github-actions-role \
  --policy-name github-actions-policy \
  --policy-document file://"$POLICY_DIR/scenario2_github_actions_identity.json" \
  --endpoint-url "$AWS_ENDPOINT_URL"

aws iam create-role \
  --role-name codepipeline-deploy-role \
  --assume-role-policy-document '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"codepipeline.amazonaws.com"},"Action":"sts:AssumeRole"}]}' \
  --endpoint-url "$AWS_ENDPOINT_URL" 2>/dev/null || true

aws iam put-role-policy \
  --role-name codepipeline-deploy-role \
  --policy-name codepipeline-policy \
  --policy-document file://"$POLICY_DIR/scenario2_codepipeline_identity.json" \
  --endpoint-url "$AWS_ENDPOINT_URL"

# Create prod role
aws iam create-role \
  --role-name codepipeline-prod-deployer \
  --assume-role-policy-document file://"$POLICY_DIR/scenario2_codepipeline_prod_trust.json" \
  --endpoint-url "$AWS_ENDPOINT_URL" 2>/dev/null || true

aws iam put-role-policy \
  --role-name codepipeline-prod-deployer \
  --policy-name codepipeline-prod-policy \
  --policy-document file://"$POLICY_DIR/scenario2_codepipeline_prod_identity.json" \
  --endpoint-url "$AWS_ENDPOINT_URL"

echo "✓ Scenario 2 roles and policies created"

# ============================================================================
# SCENARIO 3: S3 Bucket Policy Principal Boundary Confusion
# ============================================================================
echo "[Scenario 3] Seeding S3 Bucket Policy Principal Boundary..."

# developer-infrastructure-role identity policy
cat > "$POLICY_DIR/scenario3_dev_infra_identity.json" << 'EOF'
{
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
      "Action": ["s3:GetObject", "s3:ListBucket"],
      "Resource": [
        "arn:aws:s3:::org-shared-data/*",
        "arn:aws:s3:::org-shared-data"
      ]
    }
  ]
}
EOF

# Create role for Scenario 3
aws iam create-role \
  --role-name developer-infrastructure-role \
  --assume-role-policy-document '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"ec2.amazonaws.com"},"Action":"sts:AssumeRole"}]}' \
  --endpoint-url "$AWS_ENDPOINT_URL" 2>/dev/null || true

aws iam put-role-policy \
  --role-name developer-infrastructure-role \
  --policy-name dev-infra-policy \
  --policy-document file://"$POLICY_DIR/scenario3_dev_infra_identity.json" \
  --endpoint-url "$AWS_ENDPOINT_URL"

# Create S3 buckets with org-wide policy
aws s3 mb s3://org-shared-data --endpoint-url "$AWS_ENDPOINT_URL" 2>/dev/null || true
aws s3 mb s3://dev-infrastructure --endpoint-url "$AWS_ENDPOINT_URL" 2>/dev/null || true

# Set org-wide bucket policy (Principal:* with org-ID condition)
cat > "$POLICY_DIR/scenario3_bucket_policy.json" << 'EOF'
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "AllowOrgWideRead",
      "Effect": "Allow",
      "Principal": "*",
      "Action": ["s3:GetObject", "s3:ListBucket"],
      "Resource": [
        "arn:aws:s3:::org-shared-data",
        "arn:aws:s3:::org-shared-data/*"
      ],
      "Condition": {
        "StringEquals": {"aws:PrincipalOrgID": "o-myorg"}
      }
    }
  ]
}
EOF

aws s3api put-bucket-policy \
  --bucket org-shared-data \
  --policy file://"$POLICY_DIR/scenario3_bucket_policy.json" \
  --endpoint-url "$AWS_ENDPOINT_URL" 2>/dev/null || true

echo "✓ Scenario 3 roles and S3 bucket policies created"

# ============================================================================
# SCENARIO 4: KMS CreateGrant Lateral Movement
# ============================================================================
echo "[Scenario 4] Seeding KMS CreateGrant Escalation..."

# application-role identity policy
cat > "$POLICY_DIR/scenario4_application_identity.json" << 'EOF'
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "DecryptApplicationSecrets",
      "Effect": "Allow",
      "Action": ["kms:Decrypt", "kms:DescribeKey"],
      "Resource": "arn:aws:kms:us-east-1:444444444444:key/12345678-1234-1234-1234-123456789012"
    }
  ]
}
EOF

# kms-admin-role identity policy (for managing KMS key policy)
cat > "$POLICY_DIR/scenario4_kms_admin_identity.json" << 'EOF'
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "KMSManagement",
      "Effect": "Allow",
      "Action": ["kms:*"],
      "Resource": "*"
    }
  ]
}
EOF

# Create roles for Scenario 4
aws iam create-role \
  --role-name application-role \
  --assume-role-policy-document '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"lambda.amazonaws.com"},"Action":"sts:AssumeRole"}]}' \
  --endpoint-url "$AWS_ENDPOINT_URL" 2>/dev/null || true

aws iam put-role-policy \
  --role-name application-role \
  --policy-name application-policy \
  --policy-document file://"$POLICY_DIR/scenario4_application_identity.json" \
  --endpoint-url "$AWS_ENDPOINT_URL"

aws iam create-role \
  --role-name kms-admin-role \
  --assume-role-policy-document '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"iam.amazonaws.com"},"Action":"sts:AssumeRole"}]}' \
  --endpoint-url "$AWS_ENDPOINT_URL" 2>/dev/null || true

aws iam put-role-policy \
  --role-name kms-admin-role \
  --policy-name kms-admin-policy \
  --policy-document file://"$POLICY_DIR/scenario4_kms_admin_identity.json" \
  --endpoint-url "$AWS_ENDPOINT_URL"

echo "✓ Scenario 4 roles created"

# ============================================================================
# SCENARIO 5: Multi-Vector Complete Chain
# ============================================================================
echo "[Scenario 5] Seeding Complete Multi-Vector Attack Chain..."

# This scenario reuses roles from Scenarios 1-4 and adds integration points
# All roles are already created above; Scenario 5 uses combined policies

# Create a shared backdoor role that multiple scenarios can escalate to
cat > "$POLICY_DIR/scenario5_backdoor_identity.json" << 'EOF'
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "FullAdminAccess",
      "Effect": "Allow",
      "Action": "*",
      "Resource": "*"
    }
  ]
}
EOF

cat > "$POLICY_DIR/scenario5_backdoor_trust.json" << 'EOF'
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "AWS": [
          "arn:aws:iam::111111111111:role/developer-role",
          "arn:aws:iam::222222222222:role/github-actions-role",
          "arn:aws:iam::222222222222:role/codepipeline-deploy-role"
        ]
      },
      "Action": "sts:AssumeRole"
    }
  ]
}
EOF

aws iam create-role \
  --role-name multi-vector-backdoor-role \
  --assume-role-policy-document file://"$POLICY_DIR/scenario5_backdoor_trust.json" \
  --endpoint-url "$AWS_ENDPOINT_URL" 2>/dev/null || true

aws iam put-role-policy \
  --role-name multi-vector-backdoor-role \
  --policy-name backdoor-policy \
  --policy-document file://"$POLICY_DIR/scenario5_backdoor_identity.json" \
  --endpoint-url "$AWS_ENDPOINT_URL"

echo "✓ Scenario 5 backdoor role created"

# ============================================================================
# Verification and Summary
# ============================================================================
echo ""
echo "=== Adversarial Scenarios Seed Complete ==="
echo ""
echo "Scenario 1: CloudFormation Service Role Trap"
echo "  Roles: developer-role, cf-deploy-production-role, cross-account-deployer"
echo ""
echo "Scenario 2: GitHub Actions OIDC Configuration Drift"
echo "  Roles: github-actions-role, codepipeline-deploy-role, codepipeline-prod-deployer"
echo ""
echo "Scenario 3: S3 Bucket Policy Principal Boundary Confusion"
echo "  Roles: developer-infrastructure-role"
echo "  Buckets: org-shared-data (with Principal:* + org-ID policy), dev-infrastructure"
echo ""
echo "Scenario 4: KMS CreateGrant Lateral Movement"
echo "  Roles: application-role, kms-admin-role"
echo ""
echo "Scenario 5: Complete Multi-Vector Attack Chain"
echo "  Roles: multi-vector-backdoor-role (accessible from Scenario 1-4 paths)"
echo ""

# List all created roles
echo "=== Created Roles ==="
rtk aws iam list-roles --endpoint-url "$AWS_ENDPOINT_URL" --query 'Roles[].RoleName' --output text 2>/dev/null | tr '\t' '\n' | sort

echo ""
echo "=== AWS Configuration ==="
echo "Endpoint: $AWS_ENDPOINT_URL"
echo "Access Key ID: $AWS_ACCESS_KEY_ID"
echo "Default Region: $AWS_DEFAULT_REGION"
echo ""
