# ECR Lifecycle Manager Terraform Module

This Terraform configuration deploys an AWS Lambda function that automatically applies lifecycle policies to ECR pull-through cache repositories.

## Features

- **Lambda Function**: Deploys `ecr_lifecycle_manager.py` using the public `terraform-aws-modules/lambda/aws` module
- **IAM Permissions**: Comprehensive ECR read/write permissions for lifecycle policy management
- **Scheduled Execution**: Daily cron schedule via EventBridge (default: 2 AM UTC)
- **CloudWatch Logging**: Configurable log retention with proper IAM permissions
- **Dry Run Support**: Test mode to preview changes without applying them

## Prerequisites

- Terraform >= 1.0
- AWS CLI configured with appropriate permissions
- Python 3.11 runtime support in target region

## Required AWS Permissions

The deploying user/role needs permissions to create:
- Lambda functions and execution roles
- IAM policies and roles
- EventBridge rules and targets
- CloudWatch Log Groups

## Quick Start

1. **Copy and configure variables:**
   ```bash
   cp terraform.tfvars.example terraform.tfvars
   # Edit terraform.tfvars with your configuration
   ```

2. **Initialize Terraform:**
   ```bash
   terraform init
   ```

3. **Plan deployment:**
   ```bash
   terraform plan
   ```

4. **Deploy:**
   ```bash
   terraform apply
   ```

## Configuration

### Key Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `aws_region` | AWS region for deployment | `ap-southeast-2` |
| `function_name` | Lambda function name | `ecr-lifecycle-manager` |
| `schedule_expression` | Cron expression for daily run | `cron(0 2 * * ? *)` |
| `dry_run_mode` | Enable test mode | `false` |
| `log_retention_days` | CloudWatch logs retention | `14` |

### Schedule Expression Examples

- Daily at 2 AM UTC: `cron(0 2 * * ? *)`
- Daily at 6 AM UTC: `cron(0 6 * * ? *)`
- Every 12 hours: `cron(0 */12 * * ? *)`
- Weekly on Sunday at 3 AM: `cron(0 3 ? * SUN *)`

### Dry Run Mode

Set `dry_run_mode = "true"` to enable test mode:
- Identifies pull-through cache repositories
- Logs what actions would be taken
- No actual lifecycle policies are applied

## Lambda Function Details

The deployed Lambda function:

1. **Scans all ECR repositories** in the specified region
2. **Identifies pull-through cache repositories** by naming patterns:
   - `ecr-public/`
   - `docker.io/`
   - `public.ecr.aws/`
   - `quay.io/`
   - `gcr.io/`
   - `k8s.gcr.io/`
   - `registry.k8s.io/`
   - `ghcr.io/`

3. **Applies default lifecycle policy:**
   - Keep only 10 most recent images
   - Delete images older than 30 days

4. **Skips repositories** that already have lifecycle policies

## Monitoring

### CloudWatch Logs
View execution logs at:
```
/aws/lambda/<function_name>
```

### Lambda Metrics
Monitor via CloudWatch metrics:
- `Duration`: Execution time
- `Errors`: Failed executions
- `Invocations`: Total runs

### Manual Execution
Test the function manually:
```bash
aws lambda invoke \
  --function-name ecr-lifecycle-manager \
  --payload '{"source":"manual","detail":{"dry_run":"true"}}' \
  response.json
```

## Outputs

The module provides these outputs:
- `lambda_function_name`: Lambda function name
- `lambda_function_arn`: Lambda function ARN
- `lambda_role_arn`: Execution role ARN
- `cloudwatch_log_group_name`: Log group name
- `eventbridge_rule_arn`: Schedule rule ARN

## Cleanup

To remove all resources:
```bash
terraform destroy
```

## Troubleshooting

### Common Issues

1. **Permission Denied**: Ensure deploying user has sufficient AWS permissions
2. **Function Package Not Found**: Ensure `ecr_lifecycle_manager.py` exists in parent directory
3. **Invalid Cron Expression**: Verify schedule expression syntax
4. **Region Mismatch**: Ensure all resources are in the same region

### Debug Mode

Enable debug logging by setting environment variable in the Lambda:
```hcl
environment_variables = {
  AWS_REGION = data.aws_region.current.name
  DRY_RUN    = var.dry_run_mode
  LOG_LEVEL  = "DEBUG"
}
```