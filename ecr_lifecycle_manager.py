#!/usr/bin/env python3
"""AWS ECR Lifecycle Policy Manager for Pull-Through Cache Repositories"""

import json
import logging
import os
import traceback

import boto3
from botocore.exceptions import ClientError

logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)

# Lifecycle policy for pull-through cache repos
LIFECYCLE_POLICY = {
    "rules": [
        {
            "rulePriority": 1,
            "description": "Delete untagged images older than 7 days",
            "selection": {
                "tagStatus": "untagged",
                "countType": "sinceImagePushed",
                "countUnit": "days",
                "countNumber": 7,
            },
            "action": {"type": "expire"},
        },
        {
            "rulePriority": 2,
            "description": "Keep only 10 most recent images",
            "selection": {
                "tagStatus": "any",
                "countType": "imageCountMoreThan",
                "countNumber": 10,
            },
            "action": {"type": "expire"},
        },
    ]
}


def get_pullthrough_cache_prefixes(ecr_client):
    """Get ECR repository prefixes from configured pull-through cache rules."""
    try:
        response = ecr_client.describe_pull_through_cache_rules()
        prefixes = [
            rule["ecrRepositoryPrefix"] for rule in response["pullThroughCacheRules"]
        ]
        print(f"Found pull-through cache prefixes: {prefixes}")
        return prefixes
    except ClientError as e:
        print(f"Could not retrieve pull-through cache rules: {e}")
        return []


def is_pullthrough_cache_repo(repo_name, prefixes):
    """Check if repository starts with any pull-through cache prefix."""
    return any(repo_name.startswith(prefix) for prefix in prefixes)


def lambda_handler(event, context):
    """Apply ECR lifecycle policies to pull-through cache repositories."""
    print("=== ECR Lifecycle Manager started ===")
    
    try:
        print("Initializing ECR client...")
        ecr_client = boto3.client("ecr")

        dry_run_env = os.environ.get("DRY_RUN", "false")
        dry_run = dry_run_env.lower() == "true"
        print(f"DRY_RUN mode: {dry_run}")

        override_existing_env = os.environ.get("OVERRIDE_EXISTING_POLICIES", "false")
        override_existing = override_existing_env.lower() == "true"
        print(f"OVERRIDE_EXISTING_POLICIES mode: {override_existing}")

        # Get pull-through cache prefixes dynamically
        prefixes = get_pullthrough_cache_prefixes(ecr_client)

        if not prefixes:
            msg = "No pull-through cache prefixes found. No repositories will be processed."
            print(msg)
            return {
                "statusCode": 200,
                "processed": 0,
                "message": "No pull-through cache prefixes configured",
            }

        # Get all repositories
        print("Fetching ECR repositories...")
        paginator = ecr_client.get_paginator("describe_repositories")
        repositories = []
        for page in paginator.paginate():
            repositories.extend(page["repositories"])

        print(f"Found {len(repositories)} total repositories")
        
        processed = 0
        skipped = 0
        errors = 0
        
        for repo in repositories:
            repo_name = repo["repositoryName"]

            if is_pullthrough_cache_repo(repo_name, prefixes):
                print(f"Processing pull-through cache repository: {repo_name}")

                if dry_run:
                    print(f"DRY RUN: Would apply lifecycle policy to {repo_name}")
                    processed += 1
                    continue

                should_apply_policy = False

                try:
                    # Check if policy already exists
                    ecr_client.get_lifecycle_policy(repositoryName=repo_name)
                    if override_existing:
                        msg = (
                            f"Policy exists for {repo_name}, but "
                            "OVERRIDE_EXISTING_POLICIES=true, will overwrite"
                        )
                        print(msg)
                        should_apply_policy = True
                    else:
                        print(f"Policy already exists for {repo_name}, skipping")
                        skipped += 1
                except ClientError as e:
                    if e.response["Error"]["Code"] == "LifecyclePolicyNotFoundException":
                        print(f"No existing policy for {repo_name}, will apply new policy")
                        should_apply_policy = True
                    else:
                        print(f"Error checking policy for {repo_name}: {e}")
                        errors += 1

                if should_apply_policy:
                    try:
                        # Apply lifecycle policy
                        policy_json = json.dumps(LIFECYCLE_POLICY)
                        print(f"Applying policy to {repo_name}: {policy_json}")
                        ecr_client.put_lifecycle_policy(
                            repositoryName=repo_name, lifecyclePolicyText=policy_json
                        )
                        print(f"Applied lifecycle policy to {repo_name}")
                        processed += 1
                    except Exception as policy_error:
                        print(f"Error applying policy to {repo_name}: {policy_error}")
                        errors += 1
        
        summary = (
            f"Summary - Total: {len(repositories)}, Processed: {processed}, "
            f"Skipped: {skipped}, Errors: {errors}"
        )
        print(summary)

        return {
            "statusCode": 200,
            "processed": processed,
            "skipped": skipped,
            "errors": errors,
            "total_repositories": len(repositories),
        }

    except Exception as e:
        print(f"Lambda execution failed: {str(e)}")
        print(f"Traceback: {traceback.format_exc()}")
        return {"statusCode": 500, "error": str(e)}