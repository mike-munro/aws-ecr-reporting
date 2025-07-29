# ECR Pull-Through Cache and Lifecycle Management

This document outlines the setup and management of AWS ECR pull-through cache repositories and their automated lifecycle policies.

## Overview

The solution consists of two main components:
1. **ECR Pull-Through Cache Rules** - Automatically cache images from public registries
2. **Lifecycle Management Lambda** - Automatically clean up cached images based on usage

## ECR Pull-Through Cache Setup

### What is Pull-Through Cache?

ECR pull-through cache allows you to cache images from public registries (Docker Hub, ECR Public, Quay, etc.) in your private ECR registry. This provides:

- **Faster pulls** - Images cached locally in your AWS region
- **Reduced costs** - Avoid Docker Hub rate limits and egress charges
- **Better reliability** - Continue working even if upstream registry is down
- **Security scanning** - AWS Inspector scans cached images for vulnerabilities

### Common Pull-Through Cache Rules

| Registry | Upstream Registry URL | ECR Repository Prefix | Purpose |
|----------|----------------------|----------------------|---------|
| Docker Hub | `registry-1.docker.io` | `docker-hub` | Public Docker images |
| ECR Public | `public.ecr.aws` | `ecr-public` | AWS public container images |
| Quay.io | `quay.io` | `quay` | Red Hat/CoreOS images |
| Google GCR | `gcr.io` | `gcr` | Google container images |
| Kubernetes | `registry.k8s.io` | `k8s` | Kubernetes system images |
| GitHub | `ghcr.io` | `github` | GitHub container registry |

### Setting Up Pull-Through Cache Rules

#### Via AWS CLI
```bash
# Docker Hub
aws ecr create-pull-through-cache-rule \
  --ecr-repository-prefix docker-hub \
  --upstream-registry-url registry-1.docker.io

# ECR Public
aws ecr create-pull-through-cache-rule \
  --ecr-repository-prefix ecr-public \
  --upstream-registry-url public.ecr.aws

# Quay.io
aws ecr create-pull-through-cache-rule \
  --ecr-repository-prefix quay \
  --upstream-registry-url quay.io
```

#### Via Terraform
```hcl
resource "aws_ecr_pull_through_cache_rule" "docker_hub" {
  ecr_repository_prefix = "docker-hub"
  upstream_registry_url = "registry-1.docker.io"
}

resource "aws_ecr_pull_through_cache_rule" "ecr_public" {
  ecr_repository_prefix = "ecr-public"
  upstream_registry_url = "public.ecr.aws"
}

resource "aws_ecr_pull_through_cache_rule" "quay" {
  ecr_repository_prefix = "quay"
  upstream_registry_url = "quay.io"
}
```

### Using Pull-Through Cache

Once configured, pull images using your ECR registry URL with the prefix:

```bash
# Instead of: docker pull nginx:latest
docker pull 123456789012.dkr.ecr.us-east-1.amazonaws.com/docker-hub/library/nginx:latest

# Instead of: docker pull public.ecr.aws/aws-cli/aws-cli:latest
docker pull 123456789012.dkr.ecr.us-east-1.amazonaws.com/ecr-public/aws-cli/aws-cli:latest
```

## Lifecycle Management Lambda

### Purpose

The Lambda function automatically applies lifecycle policies to pull-through cache repositories to:
- **Control storage costs** - Remove unused cached images
- **Maintain only recent images** - Keep only the latest version
- **Clean up based on usage** - Remove images not pulled in 30 days

### Lifecycle Policy Rules

The Lambda applies this policy to all pull-through cache repositories:

```json
{
  "rules": [
    {
      "rulePriority": 1,
      "description": "Delete images not pulled in 30 days",
      "selection": {
        "tagStatus": "any",
        "countType": "sinceImagePulled",
        "countUnit": "days",
        "countNumber": 30
      },
      "action": {"type": "expire"}
    },
    {
      "rulePriority": 2,
      "description": "Keep only the latest 1 image",
      "selection": {
        "tagStatus": "any",
        "countType": "imageCountMoreThan",
        "countNumber": 1
      },
      "action": {"type": "expire"}
    }
  ]
}
```

**Result**: Each repository keeps maximum 1 image, and only if it was pulled within the last 30 days.

### How It Works

1. **Dynamic Discovery** - Queries `describe_pull_through_cache_rules()` to get configured prefixes
2. **Repository Scanning** - Lists all ECR repositories in the region
3. **Pattern Matching** - Identifies repos that start with pull-through cache prefixes
4. **Policy Application** - Applies lifecycle policy if none exists
5. **Logging** - Reports progress and skips repos with existing policies

### Lambda Configuration

#### Environment Variables
- `DRY_RUN`: Set to `"true"` for testing mode (default: `"false"`)

#### Required IAM Permissions
```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "ecr:DescribeRepositories",
        "ecr:ListRepositories",
        "ecr:DescribePullThroughCacheRules"
      ],
      "Resource": "*"
    },
    {
      "Effect": "Allow",
      "Action": [
        "ecr:GetLifecyclePolicy",
        "ecr:PutLifecyclePolicy",
        "ecr:DeleteLifecyclePolicy"
      ],
      "Resource": "arn:aws:ecr:*:*:repository/*"
    },
    {
      "Effect": "Allow",
      "Action": [
        "logs:CreateLogGroup",
        "logs:CreateLogStream",
        "logs:PutLogEvents"
      ],
      "Resource": "arn:aws:logs:*:*:log-group:/aws/lambda/*"
    }
  ]
}
```

### Deployment

#### Using Terraform
```bash
cd terraform
cp terraform.tfvars.example terraform.tfvars
# Edit terraform.tfvars as needed
terraform init
terraform plan
terraform apply
```

#### Schedule
- **Frequency**: Daily at 2 AM UTC
- **Trigger**: EventBridge cron rule
- **Expression**: `cron(0 2 * * ? *)`

### Testing

#### Dry Run Mode
Enable dry run to see what would be processed:
```bash
# Set environment variable
export DRY_RUN=true

# Or update Terraform variable
# dry_run_mode = "true"
```

#### Manual Execution
```bash
aws lambda invoke \
  --function-name ecr-lifecycle-manager \
  --payload '{"source":"manual"}' \
  response.json
```

## Cost Optimization

### Storage Costs
- **Before**: Unlimited image versions accumulate over time
- **After**: Maximum 1 image per repository, only if recently used
- **Savings**: Typically 70-90% reduction in ECR storage costs

### Data Transfer Costs
- **Pull-through cache**: Eliminates repeated downloads from public registries
- **Regional caching**: Images cached in your AWS region
- **Bandwidth savings**: Especially significant for frequent image pulls

## Monitoring

### CloudWatch Logs
- **Log Group**: `/aws/lambda/ecr-lifecycle-manager`
- **Retention**: 14 days (configurable)
- **Content**: Repository processing, policy applications, errors

### Key Metrics to Monitor
- **Lambda Duration**: Should complete within 5 minutes for most accounts
- **Lambda Errors**: Failed executions indicate permission or API issues
- **ECR Repository Count**: Track growth of pull-through cache repositories
- **Storage Usage**: Monitor ECR storage reduction after deployment

### Example Log Output
```
2024-01-15 02:00:15 - INFO - Found pull-through cache prefixes: ['docker-hub', 'ecr-public', 'quay']
2024-01-15 02:00:16 - INFO - Applied lifecycle policy to docker-hub/library/nginx
2024-01-15 02:00:16 - INFO - Policy already exists for ecr-public/aws-cli/aws-cli, skipping
2024-01-15 02:00:17 - INFO - Processed 15 pull-through cache repositories
```

## Troubleshooting

### Common Issues

#### No Pull-Through Cache Rules Found
- **Cause**: No pull-through cache rules configured
- **Solution**: Set up pull-through cache rules first
- **Result**: Lambda processes 0 repositories

#### Permission Denied
- **Cause**: Missing ECR permissions
- **Solution**: Verify IAM policy includes all required actions
- **Check**: `describe_pull_through_cache_rules`, `put_lifecycle_policy`

#### Lambda Timeout
- **Cause**: Too many repositories to process
- **Solution**: Increase Lambda timeout (default: 300 seconds)
- **Alternative**: Add pagination or batch processing

### Validation Commands

```bash
# Check pull-through cache rules
aws ecr describe-pull-through-cache-rules

# List repositories with lifecycle policies
aws ecr describe-repositories --query 'repositories[?lifecyclePolicyText!=null].repositoryName'

# View Lambda logs
aws logs tail /aws/lambda/ecr-lifecycle-manager --follow
```

## Security Considerations

### IAM Least Privilege
- Lambda has minimal required ECR permissions
- No cross-account access granted
- CloudWatch logs access limited to function log group

### Repository Access
- Lifecycle policies only applied to pull-through cache repositories
- Existing policies on repositories are preserved
- No access to repository contents or image data

### Audit Trail
- All policy applications logged to CloudWatch
- Lambda execution tracked via CloudTrail
- ECR API calls recorded in CloudTrail

## Best Practices

### Pull-Through Cache Rules
- **Use descriptive prefixes** - Makes repositories easily identifiable
- **Monitor usage** - Remove unused rules to reduce clutter
- **Regional deployment** - Deploy in regions where you pull images
- **Authentication** - Configure credentials for private upstream registries

### Lifecycle Policies
- **Test with dry run** - Always test policy changes first
- **Monitor storage impact** - Track storage reduction after deployment
- **Regular review** - Adjust retention periods based on usage patterns
- **Backup critical images** - For images needed long-term, consider manual repositories

### Operational
- **Schedule during low usage** - Run cleanup during off-peak hours
- **Monitor executions** - Set up CloudWatch alarms for failures
- **Document exceptions** - Note any repositories that need special handling
- **Regular updates** - Keep Lambda runtime and dependencies current