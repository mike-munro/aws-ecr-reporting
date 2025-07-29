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
        
    def get_all_repositories(self):
        """Get all ECR repositories in the region."""
        try:
            repositories = []
            paginator = self.ecr_client.get_paginator('describe_repositories')
            
            for page in paginator.paginate():
                repositories.extend(page['repositories'])
            
            logger.info(f"Found {len(repositories)} ECR repositories")
            return repositories
            
        except ClientError as e:
            logger.error(f"Error retrieving repositories: {e}")
            raise
            
    def is_pullthrough_cache_repo(self, repository):
        """
        Determine if a repository is a pull-through cache repository.
        Pull-through cache repos typically have specific naming patterns or registry IDs.
        """
        repo_name = repository['repositoryName']
        repo_uri = repository['repositoryUri']
        
        # Common patterns for pull-through cache repositories
        pullthrough_indicators = [
            'ecr-public/',
            'docker.io/',
            'public.ecr.aws/',
            'quay.io/',
            'gcr.io/',
            'k8s.gcr.io/',
            'registry.k8s.io/',
            'ghcr.io/'
        ]
        
        # Check if repo name contains pull-through cache indicators
        for indicator in pullthrough_indicators:
            if indicator in repo_name.lower():
                logger.info(f"Identified pull-through cache repo: {repo_name}")
                return True
                
        # Additional check: repositories created through pull-through cache rules
        # typically have specific registry patterns in their URIs
        if any(pattern in repo_uri for pattern in pullthrough_indicators):
            logger.info(f"Identified pull-through cache repo by URI pattern: {repo_name}")
            return True
            
        return False
        
    def get_existing_lifecycle_policy(self, repository_name):
        """Get existing lifecycle policy for a repository."""
        try:
            response = self.ecr_client.get_lifecycle_policy(
                repositoryName=repository_name
            )
            return json.loads(response['lifecyclePolicyText'])
        except ClientError as e:
            if e.response['Error']['Code'] == 'LifecyclePolicyNotFoundException':
                logger.info(f"No existing lifecycle policy found for {repository_name}")
                return None
            else:
                logger.error(f"Error getting lifecycle policy for {repository_name}: {e}")
                raise
                
    def apply_lifecycle_policy(self, repository_name, policy=None):
        """Apply lifecycle policy to a repository."""
        if policy is None:
            policy = self.default_lifecycle_policy
            
        try:
            response = self.ecr_client.put_lifecycle_policy(
                repositoryName=repository_name,
                lifecyclePolicyText=json.dumps(policy)
            )
            
            logger.info(f"✅ Successfully applied lifecycle policy to {repository_name}")
            return response
            
        except ClientError as e:
            logger.error(f"❌ Error applying lifecycle policy to {repository_name}: {e}")
            raise
            
    def process_pullthrough_repositories(self, dry_run=False):
        """
        Process all repositories and apply lifecycle policies to pull-through cache repos.
        
        Args:
            dry_run (bool): If True, only log what would be done without making changes
        """
        try:
            repositories = self.get_all_repositories()
            pullthrough_repos = []
            processed_count = 0
            error_count = 0
            
            for repo in repositories:
                repo_name = repo['repositoryName']
                
                if self.is_pullthrough_cache_repo(repo):
                    pullthrough_repos.append(repo_name)
                    
                    if dry_run:
                        logger.info(f"🔍 DRY RUN: Would apply lifecycle policy to {repo_name}")
                        processed_count += 1
                        continue
                    
                    try:
                        # Check if policy already exists
                        existing_policy = self.get_existing_lifecycle_policy(repo_name)
                        
                        if existing_policy:
                            logger.info(f"⚠️ Lifecycle policy already exists for {repo_name}, skipping")
                        else:
                            self.apply_lifecycle_policy(repo_name)
                            processed_count += 1
                            
                    except Exception as e:
                        logger.error(f"❌ Failed to process {repo_name}: {e}")
                        error_count += 1
            
            # Summary
            total_pullthrough = len(pullthrough_repos)
            action = "identified" if dry_run else "processed"
            
            logger.info(f"""
📊 SUMMARY:
   Total repositories: {len(repositories)}
   Pull-through cache repositories {action}: {total_pullthrough}
   Successfully {action}: {processed_count}
   Errors: {error_count}
   
   Pull-through cache repositories:
   {chr(10).join(f'   - {repo}' for repo in pullthrough_repos)}
            """)
            
            return {
                'total_repositories': len(repositories),
                'pullthrough_repositories': pullthrough_repos,
                'processed_count': processed_count,
                'error_count': error_count,
                'dry_run': dry_run
            }
            
        except Exception as e:
            logger.error(f"❌ Error processing repositories: {e}")
            raise

def lambda_handler(event, context):
    """
    AWS Lambda handler for ECR lifecycle policy management.
    
    Environment Variables:
        DRY_RUN: Set to 'true' for dry run mode (default: false)
    
    Note: AWS_REGION is automatically available in Lambda environment
    """
    try:
        # Get configuration from environment
        dry_run = os.environ.get('DRY_RUN', 'false').lower() == 'true'
        region = os.environ.get('AWS_REGION', 'ap-southeast-2')
        
        logger.info(f"🚀 Starting ECR Lifecycle Policy Manager")
        logger.info(f"   Region: {region}")
        logger.info(f"   Dry Run: {dry_run}")
        
        # Initialize manager (will use AWS_REGION automatically)
        manager = ECRLifecyclePolicyManager()
        
        # Process repositories
        result = manager.process_pullthrough_repositories(dry_run=dry_run)
        
        # Prepare response
        response = {
            'statusCode': 200,
            'body': json.dumps({
                'message': 'ECR lifecycle policy management completed successfully',
                'result': result,
                'timestamp': datetime.utcnow().isoformat()
            })
        }
        
        logger.info("✅ ECR Lifecycle Policy Manager completed successfully")
        return response
        
    except Exception as e:
        logger.error(f"❌ Lambda execution failed: {e}")
        return {
            'statusCode': 500,
            'body': json.dumps({
                'error': str(e),
                'timestamp': datetime.utcnow().isoformat()
            })
        }

if __name__ == "__main__":
    # For local testing
    logger.info("Running ECR Lifecycle Policy Manager locally")
    
    # Mock Lambda context for local testing
    class MockContext:
        def __init__(self):
            self.function_name = "ecr-lifecycle-manager"
            self.memory_limit_in_mb = 128
            self.invoked_function_arn = "arn:aws:lambda:ap-southeast-2:123456789012:function:ecr-lifecycle-manager"
            self.aws_request_id = "test-request-id"
    
    # Test with dry run enabled
    os.environ['DRY_RUN'] = 'true'
    os.environ['AWS_REGION'] = 'ap-southeast-2'  # For local testing
    
    result = lambda_handler({}, MockContext())
    print(json.dumps(result, indent=2))