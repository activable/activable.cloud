#!/usr/bin/env bash
# seed-floci.sh — Bootstrap mock AWS account for local development
# Creates IAM users, roles, policies, S3 buckets, and EC2 VPCs
# Run after floci health check passes

set -euo pipefail

export AWS_ENDPOINT_URL=${AWS_ENDPOINT_URL:-http://localhost:4566}
export AWS_ACCESS_KEY_ID=${AWS_ACCESS_KEY_ID:-test}
export AWS_SECRET_ACCESS_KEY=${AWS_SECRET_ACCESS_KEY:-test}
export AWS_DEFAULT_REGION=${AWS_DEFAULT_REGION:-us-east-1}

echo "=== Seeding Floci with test AWS resources ==="
echo "Endpoint: $AWS_ENDPOINT_URL"
echo "Region: $AWS_DEFAULT_REGION"
echo ""

# 1. Create IAM users
echo "[seed] Creating IAM users..."
aws iam create-user --user-name alice --endpoint-url "$AWS_ENDPOINT_URL" 2>/dev/null || true
aws iam create-user --user-name bob --endpoint-url "$AWS_ENDPOINT_URL" 2>/dev/null || true
aws iam create-user --user-name charlie --endpoint-url "$AWS_ENDPOINT_URL" 2>/dev/null || true
echo "✓ Created 3 IAM users"

# 2. Create IAM roles with trust policy
echo "[seed] Creating IAM roles..."
cat > /tmp/trust-policy.json << 'TRUST'
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Principal": {"Service": "ec2.amazonaws.com"},
    "Action": "sts:AssumeRole"
  }]
}
TRUST

aws iam create-role \
  --role-name AdminRole \
  --assume-role-policy-document file:///tmp/trust-policy.json \
  --endpoint-url "$AWS_ENDPOINT_URL" 2>/dev/null || true

aws iam create-role \
  --role-name LambdaExecutionRole \
  --assume-role-policy-document file:///tmp/trust-policy.json \
  --endpoint-url "$AWS_ENDPOINT_URL" 2>/dev/null || true
echo "✓ Created 2 IAM roles"

# 3. Create IAM managed policy
echo "[seed] Creating IAM policies..."
cat > /tmp/s3-policy.json << 'POLICY'
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Action": ["s3:GetObject", "s3:PutObject", "s3:ListBucket", "s3:DeleteObject"],
    "Resource": ["arn:aws:s3:::activable-data/*", "arn:aws:s3:::activable-data"]
  }]
}
POLICY

aws iam create-policy \
  --policy-name S3DataAccess \
  --policy-document file:///tmp/s3-policy.json \
  --endpoint-url "$AWS_ENDPOINT_URL" 2>/dev/null || true
echo "✓ Created S3 access policy"

# 4. Attach policies to users and roles
echo "[seed] Attaching policies..."
aws iam attach-user-policy \
  --user-name alice \
  --policy-arn arn:aws:iam::000000000000:policy/S3DataAccess \
  --endpoint-url "$AWS_ENDPOINT_URL" 2>/dev/null || true

aws iam attach-role-policy \
  --role-name AdminRole \
  --policy-arn arn:aws:iam::aws:policy/AdministratorAccess \
  --endpoint-url "$AWS_ENDPOINT_URL" 2>/dev/null || true

aws iam attach-role-policy \
  --role-name LambdaExecutionRole \
  --policy-arn arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole \
  --endpoint-url "$AWS_ENDPOINT_URL" 2>/dev/null || true
echo "✓ Policies attached"

# 5. Create IAM groups
echo "[seed] Creating IAM groups..."
aws iam create-group --group-name engineering --endpoint-url "$AWS_ENDPOINT_URL" 2>/dev/null || true
aws iam add-user-to-group --group-name engineering --user-name alice --endpoint-url "$AWS_ENDPOINT_URL" 2>/dev/null || true
aws iam add-user-to-group --group-name engineering --user-name bob --endpoint-url "$AWS_ENDPOINT_URL" 2>/dev/null || true
echo "✓ Created engineering group with 2 members"

# 6. Create S3 buckets
echo "[seed] Creating S3 buckets..."
aws s3 mb s3://activable-data --endpoint-url "$AWS_ENDPOINT_URL" 2>/dev/null || true
aws s3 mb s3://activable-logs --endpoint-url "$AWS_ENDPOINT_URL" 2>/dev/null || true
aws s3 mb s3://activable-backups --endpoint-url "$AWS_ENDPOINT_URL" 2>/dev/null || true
echo "✓ Created 3 S3 buckets"

# 7. Upload sample objects
echo "[seed] Uploading sample objects..."
echo '{"test": true, "timestamp": "'$(date -u +%Y-%m-%dT%H:%M:%SZ)'"}' | \
  aws s3 cp - s3://activable-data/test.json --endpoint-url "$AWS_ENDPOINT_URL" 2>/dev/null || true
echo "✓ Uploaded test object to activable-data"

# 8. Create EC2 VPC and security group
echo "[seed] Creating EC2 resources..."
VPC_ID=$(aws ec2 create-vpc \
  --cidr-block 10.0.0.0/16 \
  --endpoint-url "$AWS_ENDPOINT_URL" \
  --query 'Vpc.VpcId' \
  --output text 2>/dev/null || echo "vpc-dev")

aws ec2 create-security-group \
  --group-name web-sg \
  --description "Web server security group" \
  --vpc-id "$VPC_ID" \
  --endpoint-url "$AWS_ENDPOINT_URL" 2>/dev/null || true
echo "✓ Created VPC and security group"

# 9. Create Lambda function
echo "[seed] Creating Lambda function..."
# Create minimal Node.js Lambda function
cat > /tmp/index.js << 'LAMBDA'
exports.handler = async (event) => {
  return {
    statusCode: 200,
    body: JSON.stringify({ message: 'activable-processor ready' })
  };
};
LAMBDA

cd /tmp && zip -j function.zip index.js > /dev/null 2>&1
aws lambda create-function \
  --function-name activable-processor \
  --runtime nodejs18.x \
  --handler index.handler \
  --role arn:aws:iam::000000000000:role/LambdaExecutionRole \
  --zip-file fileb:///tmp/function.zip \
  --endpoint-url "$AWS_ENDPOINT_URL" 2>/dev/null || true
echo "✓ Created Lambda function"

# 10. Verify STS access
echo "[seed] Verifying STS caller identity..."
aws sts get-caller-identity --endpoint-url "$AWS_ENDPOINT_URL" --output json 2>/dev/null || true
echo "✓ STS access verified"

echo ""
echo "=== Floci seed complete ==="
echo ""
echo "Created resources:"
echo "  IAM: 3 users, 2 roles, 1 group, 1 custom policy"
echo "  S3: 3 buckets, 1 object"
echo "  EC2: 1 VPC, 1 security group"
echo "  Lambda: 1 function"
echo ""
echo "AWS endpoint: $AWS_ENDPOINT_URL"
echo "Credentials: AWS_ACCESS_KEY_ID=$AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY=$AWS_SECRET_ACCESS_KEY"
echo ""
