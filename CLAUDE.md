# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

This is an AWS Lambda function that generates vulnerability reports for ECR container images by pulling data from AWS Security Hub. The function consolidates ECR vulnerability findings from AWS Inspector, creates HTML and CSV reports, uploads them to S3, and sends notification summaries via SNS.

## Core Architecture

The main application is contained in `lambda.py` with a single class `SecurityHubReportGenerator` that:

1. **Data Collection**: Queries AWS Security Hub for ECR container vulnerability findings using filters
2. **Data Processing**: Consolidates duplicate CVE findings per container image to reduce noise
3. **Report Generation**: Creates HTML reports with severity breakdowns and CSV exports
4. **Storage & Notification**: Uploads reports to S3 with presigned URLs and sends summaries via SNS

### Key Components

- **SecurityHubReportGenerator** (`lambda.py:15`): Main report generation class
- **lambda_handler** (`lambda.py:648`): AWS Lambda entry point and configuration handler
- **Credential Management**: Smart S3 credential handling using either Secrets Manager (long-term) or Lambda execution role (temporary)

## Development Commands

Since this is a Python Lambda function, standard Python commands apply:

```bash
# Install dependencies (if requirements.txt existed)
pip install boto3 pandas

# Run the function locally (requires AWS credentials)
python lambda.py

# Package for Lambda deployment
zip -r lambda-package.zip lambda.py
```

## AWS Services Integration

The function integrates with:
- **AWS Security Hub**: Source of ECR vulnerability findings
- **AWS Inspector**: Original vulnerability scanner (data flows through Security Hub)
- **Amazon S3**: Report storage with presigned URL generation
- **Amazon SNS**: Email/notification delivery
- **AWS Secrets Manager**: Optional long-term S3 credentials storage

## Environment Variables

Required:
- `SNS_TOPIC_ARN`: Target SNS topic for notifications

Optional:
- `S3_BUCKET`: S3 bucket for report storage (backup disabled if not set)
- `S3_CREDENTIALS_SECRET_ID`: Secrets Manager secret for long-term S3 credentials
- `AWS_REGION`: AWS region (defaults to 'ap-southeast-2')
- `REPORT_DAYS_BACK`: Days of findings to include (default 7)
- `REPORT_URL_EXPIRY_DAYS`: Presigned URL expiry (default 7, max 7)
- `ENVIRONMENT`: Environment label for email subjects

## Key Features

- **Smart Credential Detection**: Automatically uses long-term credentials from Secrets Manager when available, falls back to Lambda execution role
- **CVE Consolidation**: Reduces duplicate findings by consolidating identical CVEs per container image
- **Intelligent URL Expiry**: Adjusts presigned URL expiration based on credential type (6 hours for temporary, up to 7 days for long-term)
- **Risk Scoring**: Prioritizes repositories by weighted severity scores
- **Multi-format Reports**: Generates HTML (visual), detailed CSV (all findings), and summary CSV (by repository)