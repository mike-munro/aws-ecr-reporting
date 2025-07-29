variable "aws_region" {
  description = "AWS region for deployment"
  type        = string
  default     = "ap-southeast-2"
}

variable "function_name" {
  description = "Name of the Lambda function"
  type        = string
  default     = "ecr-lifecycle-manager"
}

variable "schedule_expression" {
  description = "CloudWatch Events schedule expression for daily execution"
  type        = string
  default     = "cron(0 2 * * ? *)"  # Daily at 2 AM UTC
}

variable "dry_run_mode" {
  description = "Enable dry run mode (true/false)"
  type        = string
  default     = "false"
}

variable "log_retention_days" {
  description = "CloudWatch Logs retention period in days"
  type        = number
  default     = 14
}

variable "tags" {
  description = "Tags to apply to all resources"
  type        = map(string)
  default = {
    Project     = "ECR-Lifecycle-Management"
    Environment = "production"
    ManagedBy   = "terraform"
  }
}

# Optional VPC configuration
variable "vpc_subnet_ids" {
  description = "List of VPC subnet IDs for Lambda function (optional)"
  type        = list(string)
  default     = []
}

variable "vpc_security_group_ids" {
  description = "List of VPC security group IDs for Lambda function (optional)"
  type        = list(string)
  default     = []
}