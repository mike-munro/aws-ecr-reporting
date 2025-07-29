terraform {
  required_version = ">= 1.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
    archive = {
      source  = "hashicorp/archive"
      version = "~> 2.0"
    }
  }
}

provider "aws" {
  region = var.aws_region
}

# Data sources
data "aws_caller_identity" "current" {}
data "aws_region" "current" {}

# Create deployment package for Lambda
data "archive_file" "lambda_zip" {
  type        = "zip"
  source_file = "${path.module}/../ecr_lifecycle_manager.py"
  output_path = "${path.module}/ecr_lifecycle_manager.zip"
}

# IAM policy document for ECR access
data "aws_iam_policy_document" "ecr_lifecycle_policy" {
  statement {
    sid    = "ECRDescribeAccess"
    effect = "Allow"
    actions = [
      "ecr:DescribeRepositories",
      "ecr:ListRepositories",
      "ecr:DescribePullThroughCacheRules"
    ]
    resources = ["*"]
  }

  statement {
    sid    = "ECRLifecyclePolicyAccess"
    effect = "Allow"
    actions = [
      "ecr:GetLifecyclePolicy",
      "ecr:PutLifecyclePolicy",
      "ecr:DeleteLifecyclePolicy"
    ]
    resources = [
      "arn:aws:ecr:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:repository/*"
    ]
  }

  statement {
    sid    = "CloudWatchLogsAccess"
    effect = "Allow"
    actions = [
      "logs:CreateLogGroup",
      "logs:CreateLogStream",
      "logs:PutLogEvents"
    ]
    resources = [
      "arn:aws:logs:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:log-group:/aws/lambda/${var.function_name}*"
    ]
  }
}

# IAM policy for ECR lifecycle management
resource "aws_iam_policy" "ecr_lifecycle_policy" {
  name        = "${var.function_name}-ecr-policy"
  description = "IAM policy for ECR lifecycle management Lambda function"
  policy      = data.aws_iam_policy_document.ecr_lifecycle_policy.json

  tags = var.tags
}

# Lambda function using public module
module "lambda_function" {
  source = "terraform-aws-modules/lambda/aws"
  version = "~> 7.0"

  function_name = var.function_name
  description   = "Manages ECR lifecycle policies for pull-through cache repositories"
  handler       = "ecr_lifecycle_manager.lambda_handler"
  runtime       = "python3.11"
  timeout       = 300

  # Source code configuration
  create_package = false
  local_existing_package = data.archive_file.lambda_zip.output_path

  # Environment variables
  environment_variables = {
    DRY_RUN = var.dry_run_mode
  }

  # IAM configuration
  create_role = true
  role_name   = "${var.function_name}-execution-role"
  
  # Attach additional policies to the execution role
  attach_policy_statements = true
  policy_statements = {
    ecr_access = {
      effect = "Allow"
      actions = [
        "ecr:DescribeRepositories",
        "ecr:ListRepositories",
        "ecr:DescribePullThroughCacheRules",
        "ecr:GetLifecyclePolicy",
        "ecr:PutLifecyclePolicy",
        "ecr:DeleteLifecyclePolicy"
      ]
      resources = ["*"]
    }
  }

  # CloudWatch Logs configuration
  cloudwatch_logs_retention_in_days = var.log_retention_days

  # VPC configuration (if needed)
  # vpc_subnet_ids         = var.vpc_subnet_ids
  # vpc_security_group_ids = var.vpc_security_group_ids

  tags = var.tags
}

# EventBridge rule for daily cron schedule
resource "aws_cloudwatch_event_rule" "daily_schedule" {
  name                = "${var.function_name}-daily-schedule"
  description         = "Trigger ECR lifecycle policy management daily"
  schedule_expression = var.schedule_expression

  tags = var.tags
}

# EventBridge target to invoke Lambda
resource "aws_cloudwatch_event_target" "lambda_target" {
  rule      = aws_cloudwatch_event_rule.daily_schedule.name
  target_id = "ECRLifecycleManagerTarget"
  arn       = module.lambda_function.lambda_function_arn

  input = jsonencode({
    source = "eventbridge.schedule"
    detail = {
      scheduled = true
      dry_run   = var.dry_run_mode
    }
  })
}

# Permission for EventBridge to invoke Lambda
resource "aws_lambda_permission" "allow_eventbridge" {
  statement_id  = "AllowExecutionFromEventBridge"
  action        = "lambda:InvokeFunction"
  function_name = module.lambda_function.lambda_function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.daily_schedule.arn
}

# CloudWatch Log Group (created by module but we can reference it)
data "aws_cloudwatch_log_group" "lambda_logs" {
  name = "/aws/lambda/${var.function_name}"
  depends_on = [module.lambda_function]
}