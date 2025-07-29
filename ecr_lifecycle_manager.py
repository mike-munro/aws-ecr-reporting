#!/usr/bin/env python3
"""AWS ECR Lifecycle Policy Manager for Pull-Through Cache Repositories"""

import boto3
import json
import logging
import os
from botocore.exceptions import ClientError

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Lifecycle policy for pull-through cache repos
LIFECYCLE_POLICY = {
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
def get_pullthrough_cache_prefixes(ecr_client):
    """Get ECR repository prefixes from configured pull-through cache rules."""
    try:
        response = ecr_client.describe_pull_through_cache_rules()
        prefixes = [rule['ecrRepositoryPrefix'] for rule in response['pullThroughCacheRules']]
        logger.info(f"Found pull-through cache prefixes: {prefixes}")
        return prefixes
    except ClientError as e:
        logger.warning(f"Could not retrieve pull-through cache rules: {e}")
        return []

def is_pullthrough_cache_repo(repo_name, prefixes):
    """Check if repository starts with any pull-through cache prefix."""
    return any(repo_name.startswith(prefix) for prefix in prefixes)

def lambda_handler(event, context):
    """Apply ECR lifecycle policies to pull-through cache repositories."""
    ecr_client = boto3.client('ecr')
    dry_run = os.environ.get('DRY_RUN', 'false').lower() == 'true'
    
    try:
        # Get pull-through cache prefixes dynamically
        prefixes = get_pullthrough_cache_prefixes(ecr_client)
        
        # Get all repositories
        paginator = ecr_client.get_paginator('describe_repositories')
        repositories = []
        for page in paginator.paginate():
            repositories.extend(page['repositories'])
        
        processed = 0
        for repo in repositories:
            repo_name = repo['repositoryName']
            
            if is_pullthrough_cache_repo(repo_name, prefixes):
                if dry_run:
                    logger.info(f"DRY RUN: Would apply lifecycle policy to {repo_name}")
                    processed += 1
                    continue
                
                try:
                    # Check if policy already exists
                    ecr_client.get_lifecycle_policy(repositoryName=repo_name)
                    logger.info(f"Policy already exists for {repo_name}, skipping")
                except ClientError as e:
                    if e.response['Error']['Code'] == 'LifecyclePolicyNotFoundException':
                        # Apply lifecycle policy
                        ecr_client.put_lifecycle_policy(
                            repositoryName=repo_name,
                            lifecyclePolicyText=json.dumps(LIFECYCLE_POLICY)
                        )
                        logger.info(f"Applied lifecycle policy to {repo_name}")
                        processed += 1
                    else:
                        logger.error(f"Error checking {repo_name}: {e}")
        
        logger.info(f"Processed {processed} pull-through cache repositories")
        return {'statusCode': 200, 'processed': processed}
        
    except Exception as e:
        logger.error(f"Lambda execution failed: {e}")
        return {'statusCode': 500, 'error': str(e)}