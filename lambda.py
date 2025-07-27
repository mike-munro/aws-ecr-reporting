#!/usr/bin/env python3
"""AWS Security Hub ECR Vulnerability Reporter"""

import boto3
import json
import pandas as pd
from datetime import datetime, timedelta, timezone
import logging
import os
from botocore.exceptions import ClientError

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class ECRVulnerabilityReportGenerator:
    def __init__(self, region_name='us-east-1', sns_topic_arn=None):
        self.region_name = region_name
        self.sns_topic_arn = sns_topic_arn
        
        # Initialize clients with appropriate credentials
        self._initialize_clients()
        
    def _initialize_clients(self):
        """Initialize AWS clients with appropriate credentials."""
        # Use Lambda execution role for Inspector, SecurityHub and SNS
        self.inspector_client = boto3.client('inspector2', region_name=self.region_name)
        self.securityhub_client = boto3.client('securityhub', region_name=self.region_name)
        self.sns_client = boto3.client('sns', region_name=self.region_name)
        
        # Initialize S3 client with long-term credentials if available
        self.s3_client = self._get_s3_client_with_long_term_creds()
        
    def _get_s3_client_with_long_term_creds(self):
        """Get S3 client using long-term credentials from Secrets Manager."""
        try:
            # Try to get credentials from Secrets Manager
            secret_id = os.environ.get('S3_CREDENTIALS_SECRET_ID')
            secrets_client = boto3.client('secretsmanager', region_name=self.region_name)
            
            try:
                if not secret_id:
                    logger.warning("⚠️ S3_CREDENTIALS_SECRET_ID environment variable not set")
                    raise ClientError({'Error': {'Code': 'ResourceNotFoundException'}}, 'GetSecretValue')
                
                response = secrets_client.get_secret_value(SecretId=secret_id)
                secret_data = json.loads(response['SecretString'])
                
                access_key = secret_data.get('access_key_id')
                secret_key = secret_data.get('secret_access_key')
                
                if access_key and secret_key:
                    logger.info("✅ Using long-term S3 credentials from Secrets Manager")
                    return boto3.client(
                        's3',
                        region_name=self.region_name,
                        aws_access_key_id=access_key,
                        aws_secret_access_key=secret_key
                    )
                else:
                    logger.warning("⚠️ Secrets Manager credentials incomplete")
                    
            except ClientError as e:
                if e.response['Error']['Code'] == 'ResourceNotFoundException':
                    logger.warning(f"⚠️ Secrets Manager secret not found: {secret_id}")
                else:
                    logger.warning(f"⚠️ Could not retrieve credentials from Secrets Manager: {e}")
            
            # Fall back to Lambda execution role (shorter expiry)
            logger.warning("⚠️ Using Lambda execution role - URLs will have shorter expiry")
            return boto3.client('s3', region_name=self.region_name)
            
        except Exception as e:
            logger.error(f"❌ Error initializing S3 client: {e}")
            return boto3.client('s3', region_name=self.region_name)
    
    def _detect_credential_type(self):
        """Detect whether we're using long-term or temporary credentials."""
        try:
            # Check the S3 client credentials
            s3_credentials = self.s3_client._get_credentials()
            
            if hasattr(s3_credentials, 'token') and s3_credentials.token:
                return 'temporary'
            else:
                return 'long-term'
                
        except Exception as e:
            logger.warning(f"Could not detect credential type: {e}")
            return 'unknown'
    
    def generate_presigned_url_with_smart_expiry(self, bucket, key, requested_expiry_days=7):
        """Generate presigned URL with intelligent expiry based on credential type."""
        try:
            credential_type = self._detect_credential_type()
            
            # Calculate maximum safe expiry based on credential type
            if credential_type == 'long-term':
                # Long-term credentials: use full requested expiry (up to 7 days)
                max_expiry_seconds = min(requested_expiry_days * 24 * 60 * 60, 7 * 24 * 60 * 60)
                logger.info(f"✅ Using long-term credentials: {requested_expiry_days} day expiry")
            else:
                # Temporary credentials: limit to 6 hours for safety
                max_expiry_seconds = min(6 * 60 * 60, requested_expiry_days * 24 * 60 * 60)
                actual_hours = max_expiry_seconds / 3600
                logger.warning(f"⚠️ Using temporary credentials: limited to {actual_hours} hour expiry")
            
            # Generate the presigned URL
            presigned_url = self.s3_client.generate_presigned_url(
                'get_object',
                Params={'Bucket': bucket, 'Key': key},
                ExpiresIn=max_expiry_seconds
            )
            
            # Calculate actual expiry time
            expiry_time = datetime.now(timezone.utc) + timedelta(seconds=max_expiry_seconds)
            logger.info(f"📅 Presigned URL expires at: {expiry_time.isoformat()} UTC")
            
            return presigned_url, max_expiry_seconds, credential_type
            
        except Exception as e:
            logger.error(f"❌ Error generating presigned URL: {e}")
            raise
        
    def get_ecr_findings_from_inspector(self, days_back=7):
        """Get ECR container vulnerability findings directly from Amazon Inspector with container usage data."""
        try:
            end_date = datetime.now()
            start_date = end_date - timedelta(days=days_back)
            
            # Inspector filter criteria for ECR container image findings
            filter_criteria = {
                'resourceType': [{'comparison': 'EQUALS', 'value': 'ECR_CONTAINER_IMAGE'}],
                'updatedAt': [{
                    'startInclusive': start_date,
                    'endInclusive': end_date
                }],
                'findingStatus': [{'comparison': 'EQUALS', 'value': 'ACTIVE'}]
            }
            
            findings = []
            paginator = self.inspector_client.get_paginator('list_findings')
            
            logger.info(f"Querying Inspector for ECR findings from {start_date.strftime('%Y-%m-%d')} to {end_date.strftime('%Y-%m-%d')}")
            
            for page in paginator.paginate(filterCriteria=filter_criteria):
                findings.extend(page['findings'])
                
            logger.info(f"Retrieved {len(findings)} ECR vulnerability findings from Inspector")
            return findings
            
        except ClientError as e:
            logger.error(f"Error retrieving ECR findings from Inspector: {e}")
            # Fallback to Security Hub if Inspector fails
            logger.info("Falling back to Security Hub for findings retrieval")
            return self._get_ecr_findings_from_security_hub(days_back)
        
    def _get_ecr_findings_from_security_hub(self, days_back=7):
        """Fallback method to get ECR findings from Security Hub."""
        try:
            end_date = datetime.now()
            start_date = end_date - timedelta(days=days_back)
            
            filters = {
                'ResourceType': [{'Value': 'AwsEcrContainerImage', 'Comparison': 'EQUALS'}],
                'ProductName': [{'Value': 'Inspector', 'Comparison': 'EQUALS'}],
                'Type': [{'Value': 'Software and Configuration Checks/Vulnerabilities/CVE', 'Comparison': 'EQUALS'}],
                'UpdatedAt': [{'Start': start_date.isoformat(), 'End': end_date.isoformat()}],
                'RecordState': [{'Value': 'ACTIVE', 'Comparison': 'EQUALS'}]
            }
            
            findings = []
            paginator = self.securityhub_client.get_paginator('get_findings')
            for page in paginator.paginate(Filters=filters):
                findings.extend(page['Findings'])
                
            logger.info(f"Retrieved {len(findings)} ECR vulnerability findings from Security Hub (fallback)")
            return findings
        except ClientError as e:
            logger.error(f"Error retrieving ECR findings from Security Hub: {e}")
            return []
    
    def process_findings_data(self, findings):
        """Process Security Hub findings into structured data."""
        processed_data = []
        
        for finding in findings:
            finding_data = {
                'id': finding.get('Id', ''), 'aws_account_id': finding.get('AwsAccountId', ''),
                'region': finding.get('Region', ''), 'title': finding.get('Title', ''),
                'description': finding.get('Description', ''), 'severity_label': finding.get('Severity', {}).get('Label', ''),
                'confidence': finding.get('Confidence', 0), 'criticality': finding.get('Criticality', 0),
                'product_name': finding.get('ProductName', ''), 'generator_id': finding.get('GeneratorId', ''),
                'type': ', '.join(finding.get('Types', [])), 'created_at': finding.get('CreatedAt', ''),
                'updated_at': finding.get('UpdatedAt', ''), 'record_state': finding.get('RecordState', ''),
                'workflow_state': finding.get('Workflow', {}).get('Status', ''),
                'compliance_status': finding.get('Compliance', {}).get('Status', ''), 'resources': []
            }
            
            for resource in finding.get('Resources', []):
                resource_data = {
                    'resource_id': resource.get('Id', ''), 'resource_type': resource.get('Type', ''),
                    'resource_region': resource.get('Region', ''), 'resource_tags': json.dumps(resource.get('Tags', {})),
                    'resource_details': json.dumps(resource.get('Details', {}))
                }
                finding_data['resources'].append(resource_data)
            
            processed_data.append(finding_data)
        
        flattened_data = []
        for finding in processed_data:
            if finding['resources']:
                for resource in finding['resources']:
                    row = {**finding, **resource}
                    del row['resources']
                    flattened_data.append(row)
            else:
                del finding['resources']
                flattened_data.append(finding)
        
        df = pd.DataFrame(flattened_data)
        for col in ['created_at', 'updated_at']:
            if col in df.columns:
                df[col] = pd.to_datetime(df[col], errors='coerce')
        
        return df
    
    def process_inspector_findings_data(self, findings):
        """Process Inspector findings into structured data with container usage information."""
        processed_data = []
        
        for finding in findings:
            # Extract basic finding information
            finding_data = {
                'id': finding.get('findingArn', ''),
                'aws_account_id': finding.get('awsAccountId', ''),
                'region': finding.get('region', ''),
                'title': finding.get('title', ''),
                'description': finding.get('description', ''),
                'severity_label': finding.get('severity', ''),
                'inspector_score': finding.get('inspectorScore', 0),
                'inspector_score_details': json.dumps(finding.get('inspectorScoreDetails', {})),
                'type': finding.get('type', ''),
                'created_at': finding.get('firstObservedAt', ''),
                'updated_at': finding.get('updatedAt', ''),
                'status': finding.get('status', ''),
                'remediation': json.dumps(finding.get('remediation', {})),
                'package_vulnerability_details': json.dumps(finding.get('packageVulnerabilityDetails', {})),
                'resources': []
            }
            
            # Process resources with enhanced container usage data
            for resource in finding.get('resources', []):
                resource_data = {
                    'resource_id': resource.get('id', ''),
                    'resource_type': resource.get('type', ''),
                    'resource_region': resource.get('region', ''),
                    'resource_tags': json.dumps(resource.get('tags', {})),
                    'resource_details': json.dumps(resource.get('details', {}))
                }
                
                # Extract ECR container image specific details
                if resource.get('type') == 'ECR_CONTAINER_IMAGE':
                    ecr_details = resource.get('details', {}).get('ecrContainerImage', {})
                    resource_data.update({
                        'repository_name': ecr_details.get('repositoryName', ''),
                        'image_id': ecr_details.get('imageId', ''),
                        'image_tags': json.dumps(ecr_details.get('imageTags', [])),
                        'platform': ecr_details.get('platform', ''),
                        'pushed_at': ecr_details.get('pushedAt', ''),
                        # Enhanced container usage data from Inspector
                        'last_in_use_at': ecr_details.get('lastInUseAt', ''),
                        'in_use_count': ecr_details.get('inUseCount', 0),
                        'registry_id': ecr_details.get('registryId', ''),
                        'repository_arn': ecr_details.get('repositoryArn', '')
                    })
                
                finding_data['resources'].append(resource_data)
            
            processed_data.append(finding_data)
        
        # Flatten data for DataFrame processing
        flattened_data = []
        for finding in processed_data:
            if finding['resources']:
                for resource in finding['resources']:
                    row = {**finding, **resource}
                    del row['resources']
                    flattened_data.append(row)
            else:
                del finding['resources']
                flattened_data.append(finding)
        
        df = pd.DataFrame(flattened_data)
        
        # Convert date columns
        date_columns = ['created_at', 'updated_at', 'pushed_at', 'last_in_use_at']
        for col in date_columns:
            if col in df.columns:
                df[col] = pd.to_datetime(df[col], errors='coerce')
        
        # Convert numeric columns
        if 'in_use_count' in df.columns:
            df['in_use_count'] = pd.to_numeric(df['in_use_count'], errors='coerce').fillna(0)
        if 'inspector_score' in df.columns:
            df['inspector_score'] = pd.to_numeric(df['inspector_score'], errors='coerce').fillna(0)
        
        return df

    def consolidate_findings(self, df):
        """Consolidate duplicate CVE findings per container image."""
        if df.empty:
            return df
        
        logger.info(f"Consolidating findings... Original count: {len(df)}")
        
        # Use Inspector repository_name if available, otherwise extract from resource_id
        if 'repository_name' in df.columns:
            df['image_repository'] = df['repository_name'].fillna(
                df['resource_id'].str.extract(r'repository/([^/]+(?:/[^/]+)*?)(?:/sha256:|$)')[0]
            )
        else:
            df['image_repository'] = df['resource_id'].str.extract(r'repository/([^/]+(?:/[^/]+)*?)(?:/sha256:|$)')
        
        df['cve_id'] = df['title'].str.extract(r'(CVE-\d{4}-\d+)')
        df['cve_id'] = df['cve_id'].fillna('UNKNOWN-CVE')
        df['image_repository'] = df['image_repository'].fillna('UNKNOWN-REPO')
        
        severity_rank = {'CRITICAL': 4, 'HIGH': 3, 'MEDIUM': 2, 'LOW': 1, 'INFORMATIONAL': 0}
        df['severity_rank'] = df['severity_label'].map(severity_rank).fillna(0)
        
        consolidated_data = []
        for (image_repo, cve_id), group in df.groupby(['image_repository', 'cve_id']):
            best_finding = group.loc[group['severity_rank'].idxmax()] if len(group) > 1 else group.iloc[0]
            duplicate_count = len(group)
            affected_resources = group['resource_id'].unique()
            
            row_dict = best_finding.to_dict()
            row_dict['duplicate_count'] = duplicate_count
            row_dict['affected_layers'] = len(affected_resources)
            
            if duplicate_count > 1:
                original_desc = row_dict.get('description', '')
                row_dict['description'] = f"{original_desc} [CONSOLIDATED: Found in {duplicate_count} layers]"
            
            consolidated_data.append(row_dict)
        
        consolidated_df = pd.DataFrame(consolidated_data)
        logger.info(f"Reduced from {len(df)} to {len(consolidated_df)} findings")
        return consolidated_df
    
    def generate_summary_stats(self, df):
        """Generate summary statistics with enhanced container usage analysis."""
        if df.empty:
            return {'total_findings': 0, 'total_unique_cves': 0, 'total_duplicates_eliminated': 0,
            'total_scanned_images': 0, 'total_active_images': 0, 'total_inactive_images': 0, 
            'severity_breakdown': {}, 'accounts_affected': 0}
        
        total_duplicates = df['duplicate_count'].sum() - len(df)
        unique_cves = df['cve_id'].nunique()
        total_scanned_images = df['resource_id'].nunique()
        
        # Enhanced active image calculation using Inspector container usage data
        active_images = set()
        inactive_images = set()
        
        # Check if we have Inspector container usage data
        if 'in_use_count' in df.columns and 'last_in_use_at' in df.columns:
            logger.info("Using Inspector container usage data for active image calculation")
            
            # Images are considered active if they have in_use_count > 0 or recent last_in_use_at
            current_time = datetime.now()
            recent_threshold = current_time - timedelta(days=30)  # Consider images used in last 30 days as potentially active
            
            for _, row in df.iterrows():
                resource_id = row.get('resource_id', '')
                in_use_count = row.get('in_use_count', 0)
                last_in_use_at = row.get('last_in_use_at')
                
                if resource_id:
                    # Image is active if currently in use OR recently used
                    is_active = False
                    if in_use_count > 0:
                        is_active = True
                    elif pd.notna(last_in_use_at) and last_in_use_at >= recent_threshold:
                        is_active = True
                    
                    if is_active:
                        active_images.add(resource_id)
                    else:
                        inactive_images.add(resource_id)
            
            total_active_images = len(active_images)
            total_inactive_images = len(inactive_images)
            
            logger.info(f"Container usage analysis: {total_active_images} active, {total_inactive_images} inactive images")
        else:
            # Fallback to original logic if Inspector data not available
            logger.warning("Inspector container usage data not available, using fallback counting")
            total_active_images = total_scanned_images
            total_inactive_images = 0
        
        severity_scores = {'CRITICAL': 10, 'HIGH': 7, 'MEDIUM': 5, 'LOW': 3, 'INFORMATIONAL': 1}
        df['custom_criticality'] = df['severity_label'].map(severity_scores).fillna(0)
        avg_criticality = df['custom_criticality'].mean()
        
        # Enhanced repository analysis with severity breakdown
        repo_stats = []
        for repo_name, repo_group in df.groupby('image_repository'):
            if repo_name and str(repo_name) != 'nan' and repo_name != 'UNKNOWN-REPO':
                severity_counts = repo_group['severity_label'].value_counts()
                critical_count = severity_counts.get('CRITICAL', 0)
                high_count = severity_counts.get('HIGH', 0)
                medium_count = severity_counts.get('MEDIUM', 0)
                low_count = severity_counts.get('LOW', 0)
                info_count = severity_counts.get('INFORMATIONAL', 0)
                
                # Calculate risk score for sorting
                risk_score = (critical_count * 10) + (high_count * 7) + (medium_count * 5) + (low_count * 3) + (info_count * 1)
                
                # Enhanced repository analysis with container usage data
                repo_active_images = 0
                repo_inactive_images = 0
                
                if 'in_use_count' in repo_group.columns:
                    # Count active vs inactive images for this repository
                    for _, row in repo_group.iterrows():
                        in_use_count = row.get('in_use_count', 0)
                        last_in_use_at = row.get('last_in_use_at')
                        
                        is_active = False
                        if in_use_count > 0:
                            is_active = True
                        elif pd.notna(last_in_use_at) and last_in_use_at >= recent_threshold:
                            is_active = True
                        
                        if is_active:
                            repo_active_images += 1
                        else:
                            repo_inactive_images += 1
                
                repo_stats.append({
                    'repository': repo_name,
                    'unique_cves': repo_group['cve_id'].nunique(),
                    'total_findings': len(repo_group),
                    'critical': critical_count,
                    'high': high_count,
                    'medium': medium_count,
                    'low': low_count,
                    'informational': info_count,
                    'risk_score': risk_score,
                    'active_images': repo_active_images,
                    'inactive_images': repo_inactive_images,
                    'total_in_use_count': repo_group.get('in_use_count', pd.Series([0])).sum()
                })
        
        # Sort by risk score (descending), then by unique CVEs (descending)
        repo_stats = sorted(repo_stats, key=lambda x: (x['risk_score'], x['unique_cves']), reverse=True)
        
        return {
            'total_findings': len(df), 
            'total_unique_cves': unique_cves,
            'total_duplicates_eliminated': int(total_duplicates), 
            'total_scanned_images': total_scanned_images,
            'total_active_images': total_active_images,
            'total_inactive_images': total_inactive_images,
            'active_image_percentage': round((total_active_images / max(total_scanned_images, 1)) * 100, 1),
            'severity_breakdown': df['severity_label'].value_counts().to_dict(), 
            'avg_criticality': avg_criticality,
            'accounts_affected': df['aws_account_id'].nunique(), 
            'regions_affected': df['region'].nunique(),
            'top_repositories': {repo['repository']: repo['unique_cves'] for repo in repo_stats[:10]},  # Keep existing format for compatibility
            'repository_details': repo_stats[:20],  # Add detailed breakdown for top 20 repositories
            'container_usage_available': 'in_use_count' in df.columns and 'last_in_use_at' in df.columns
        }

    def create_html_report(self, df, summary):
        """Create HTML report from consolidated data."""
        html_content = f"""<!DOCTYPE html>
    <html><head><meta charset="UTF-8"><title>ECR Vulnerability Report</title>
    <style>
    body {{ font-family: Arial, sans-serif; margin: 20px; }}
    .header {{ background-color: #f8f9fa; padding: 20px; border-radius: 5px; border-left: 4px solid #007bff; }}
    .summary {{ background-color: #e9ecef; padding: 15px; margin: 20px 0; border-radius: 5px; }}
    table {{ border-collapse: collapse; width: 100%; margin: 20px 0; }}
    th, td {{ border: 1px solid #dee2e6; padding: 12px; text-align: left; }}
    th {{ background-color: #f8f9fa; font-weight: bold; }}
    .metric-card {{ display: inline-block; background: #fff; padding: 15px; margin: 10px; border-radius: 5px; 
                box-shadow: 0 2px 4px rgba(0,0,0,0.1); min-width: 150px; text-align: center; }}
    .metric-value {{ font-size: 24px; font-weight: bold; color: #007bff; }}
    .metric-label {{ font-size: 14px; color: #6c757d; }}
    .critical {{ color: #dc3545; font-weight: bold; }}
    .high {{ color: #fd7e14; font-weight: bold; }}
    .medium {{ color: #856404; font-weight: bold; }}
    .low {{ color: #6c757d; }}
    .informational {{ color: #17a2b8; }}
    .cve-description {{ font-size: 12px; line-height: 1.4; }}
    .cve-id {{ white-space: nowrap !important; min-width: 130px; font-weight: bold; }}
    td.cve-id {{ white-space: nowrap !important; }}
    .severity-badge {{ display: inline-block; padding: 2px 6px; border-radius: 3px; font-size: 11px; font-weight: bold; margin: 1px; }}
    .badge-critical {{ background-color: #dc3545; color: white; }}
    .badge-high {{ background-color: #fd7e14; color: white; }}
    .badge-medium {{ background-color: #ffc107; color: #212529; }}
    .badge-low {{ background-color: #6c757d; color: white; }}
    .badge-informational {{ background-color: #17a2b8; color: white; }}
    .repo-name {{ font-weight: bold; }}
    .risk-score {{ text-align: center; font-weight: bold; }}
    .severity-counts {{ text-align: center; }}
    </style></head><body>
    <div class="header">
    <h1>🐳 ECR Container Vulnerability Report</h1>
    <p><strong>Generated:</strong> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
    <p><strong>Source:</strong> AWS ECR → AWS Inspector → AWS Security Hub</p>
    </div>

    <div class="summary">
    <h2>📊 Executive Summary</h2>
    <div class="metric-card"><div class="metric-value">{summary['total_active_images']}</div><div class="metric-label">Active Images</div></div>
    <div class="metric-card"><div class="metric-value">{summary.get('total_inactive_images', 0)}</div><div class="metric-label">Inactive Images</div></div>
    <div class="metric-card"><div class="metric-value">{summary['total_findings']}</div><div class="metric-label">Vulnerabilities</div></div>
    <div class="metric-card"><div class="metric-value">{summary['total_unique_cves']}</div><div class="metric-label">Unique CVEs</div></div>
    <div class="metric-card"><div class="metric-value">{summary.get('active_image_percentage', 0)}%</div><div class="metric-label">Active Rate</div></div>
    <div class="metric-card"><div class="metric-value">{summary['avg_criticality']:.1f}</div><div class="metric-label">Avg Criticality</div></div>

    <h3 style="margin-top: 30px; margin-bottom: 15px;">Severity Breakdown</h3>"""
        
        for severity in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFORMATIONAL']:
            if severity in summary['severity_breakdown']:
                count = summary['severity_breakdown'][severity]
                severity_class = severity.lower()
                html_content += f'<div class="metric-card"><div class="metric-value {severity_class}">{count}</div><div class="metric-label">{severity}</div></div>'
        
        # Add container usage summary if available
        if summary.get('container_usage_available', False):
            html_content += f"""
    <h3 style="margin-top: 30px; margin-bottom: 15px;">📈 Container Usage Analysis</h3>
    <p><strong>Enhanced reporting using Amazon Inspector container mapping:</strong></p>
    <ul>
    <li>✅ <strong>Active Images:</strong> {summary['total_active_images']} images currently in use or recently used (last 30 days)</li>
    <li>⚠️ <strong>Inactive Images:</strong> {summary.get('total_inactive_images', 0)} images with vulnerabilities but not currently running</li>
    <li>📊 <strong>Usage Rate:</strong> {summary.get('active_image_percentage', 0)}% of vulnerable images are actively used</li>
    </ul>
    <p><em>Focus remediation efforts on the {summary['total_active_images']} active images to maximize security impact.</em></p>
"""
        else:
            html_content += f"""
    <h3 style="margin-top: 30px; margin-bottom: 15px;">⚠️ Container Usage Data</h3>
    <p><strong>Note:</strong> Enhanced container usage data from Amazon Inspector is not available. Image counts reflect all scanned images.</p>
    <p><em>To enable container usage tracking, ensure Amazon Inspector container mapping is activated.</em></p>
"""
        
        html_content += f"""</div>

    <h2>🏆 Top 20 Affected Repositories</h2>
    <p><em>Repositories ranked by risk score (weighted by severity). Showing detailed severity breakdown for prioritized remediation.</em></p>
    <table>
    <tr>
        <th>Repository</th>
        <th>Risk Score</th>
        <th>Total CVEs</th>
        <th>Severity Breakdown</th>
        <th>Details</th>
    </tr>"""
        
        # Use the enhanced repository details if available, otherwise fall back to basic format
        if 'repository_details' in summary and summary['repository_details']:
            for repo_data in summary['repository_details']:
                repo_name = repo_data['repository']
                risk_score = repo_data['risk_score']
                unique_cves = repo_data['unique_cves']
                total_findings = repo_data['total_findings']
                
                # Build severity breakdown with badges
                severity_badges = []
                if repo_data['critical'] > 0:
                    severity_badges.append(f'<span class="severity-badge badge-critical">C: {repo_data["critical"]}</span>')
                if repo_data['high'] > 0:
                    severity_badges.append(f'<span class="severity-badge badge-high">H: {repo_data["high"]}</span>')
                if repo_data['medium'] > 0:
                    severity_badges.append(f'<span class="severity-badge badge-medium">M: {repo_data["medium"]}</span>')
                if repo_data['low'] > 0:
                    severity_badges.append(f'<span class="severity-badge badge-low">L: {repo_data["low"]}</span>')
                if repo_data['informational'] > 0:
                    severity_badges.append(f'<span class="severity-badge badge-informational">I: {repo_data["informational"]}</span>')
                
                severity_display = ''.join(severity_badges) if severity_badges else '<span class="severity-badge badge-low">None</span>'
                
                # Determine priority indicator
                if repo_data['critical'] > 0:
                    priority_icon = "🚨"
                elif repo_data['high'] > 0:
                    priority_icon = "⚠️"
                elif repo_data['medium'] > 0:
                    priority_icon = "📋"
                else:
                    priority_icon = "📝"
                
                details = f"{total_findings} findings" if total_findings != unique_cves else f"{unique_cves} findings"
                
                html_content += f'''<tr>
        <td class="repo-name">{priority_icon} {repo_name}</td>
        <td class="risk-score">{risk_score}</td>
        <td class="severity-counts">{unique_cves}</td>
        <td class="severity-counts">{severity_display}</td>
        <td>{details}</td>
    </tr>'''
        else:
            # Fallback to original format if repository_details not available
            for repo_name, unique_cves in summary['top_repositories'].items():
                if repo_name and str(repo_name) != 'nan':
                    html_content += f'<tr><td class="repo-name">{repo_name}</td><td>-</td><td>{unique_cves}</td><td>-</td><td>-</td></tr>'
        
        html_content += """</table>
    <p><strong>Legend:</strong> C=Critical, H=High, M=Medium, L=Low, I=Informational. Risk Score = (Critical×10) + (High×7) + (Medium×5) + (Low×3) + (Info×1)</p>

    <h2>🚨 Critical & High Severity CVEs</h2>"""
        
        if not df.empty:
            # Filter for critical and high severity CVEs only
            critical_high_cves = df[df['severity_label'].isin(['CRITICAL', 'HIGH'])]
            
            if not critical_high_cves.empty:
                # Count frequency of each CVE for sorting
                cve_frequency = critical_high_cves['cve_id'].value_counts()
                critical_high_cves = critical_high_cves.copy()
                critical_high_cves['cve_frequency'] = critical_high_cves['cve_id'].map(cve_frequency)
                
                # Remove duplicates to get unique CVEs
                unique_critical_high_cves = critical_high_cves.drop_duplicates(subset=['cve_id'])
                
                # Separate critical and high severity CVEs
                critical_cves = unique_critical_high_cves[unique_critical_high_cves['severity_label'] == 'CRITICAL']
                high_cves = unique_critical_high_cves[unique_critical_high_cves['severity_label'] == 'HIGH']
                
                # Sort critical CVEs by frequency (descending), then by CVE ID
                critical_cves = critical_cves.sort_values(['cve_frequency', 'cve_id'], ascending=[False, True])
                
                # Sort high CVEs by frequency (descending), then by CVE ID, and take top 25
                high_cves = high_cves.sort_values(['cve_frequency', 'cve_id'], ascending=[False, True]).head(25)
                
                # Display CRITICAL CVEs (all of them)
                if not critical_cves.empty:
                    critical_count = len(critical_cves)
                    html_content += f"""<h3 class="critical">CRITICAL Severity (All {critical_count} CVEs)</h3>
    <table><tr><th>CVE ID</th><th>Repository</th><th>Frequency</th><th>Description</th></tr>"""
                    
                    for _, row in critical_cves.iterrows():
                        cve_id = row['cve_id']
                        repo = row['image_repository']
                        frequency = row['cve_frequency']
                        desc = row['description']
                        if cve_id and str(cve_id) != 'nan':
                            html_content += f'<tr><td class="cve-id">{cve_id}</td><td>{repo}</td><td>{frequency}</td><td class="cve-description">{desc}</td></tr>'
                    
                    html_content += '</table>'
                
                # Display HIGH CVEs (top 25 only)
                if not high_cves.empty:
                    total_high_count = len(unique_critical_high_cves[unique_critical_high_cves['severity_label'] == 'HIGH'])
                    displayed_high_count = len(high_cves)
                    
                    if total_high_count > 25:
                        html_content += f"""<h3 class="high">HIGH Severity (Top {displayed_high_count} of {total_high_count} CVEs)</h3>
    <p><em>Showing the top 25 most frequent High severity vulnerabilities out of {total_high_count} total, sorted by frequency across repositories.</em></p>"""
                    else:
                        html_content += f"""<h3 class="high">HIGH Severity (All {displayed_high_count} CVEs)</h3>"""
                    
                    html_content += """<table><tr><th>CVE ID</th><th>Repository</th><th>Frequency</th><th>Description</th></tr>"""
                    
                    for _, row in high_cves.iterrows():
                        cve_id = row['cve_id']
                        repo = row['image_repository']
                        frequency = row['cve_frequency']
                        desc = row['description']
                        if cve_id and str(cve_id) != 'nan':
                            html_content += f'<tr><td class="cve-id">{cve_id}</td><td>{repo}</td><td>{frequency}</td><td class="cve-description">{desc}</td></tr>'
                    
                    html_content += '</table>'
            else:
                html_content += '<p>No Critical or High severity vulnerabilities found.</p>'
        
        html_content += f"""

    <h2>📊 Container Security Analysis</h2>
    <p>Complete vulnerability details for your ECR container images are available via the download links provided in the original email notification. This includes:</p>
    <ul>
    <li><strong>CVE Details:</strong> Specific vulnerability IDs and descriptions</li>
    <li><strong>Package Information:</strong> Affected packages and versions</li>
    <li><strong>Container Metadata:</strong> Repository names, image tags, and digests</li>
    <li><strong>Severity Scoring:</strong> CVSS scores and Inspector assessments</li>
    <li><strong>Resource Context:</strong> AWS account, region, and resource details</li>
    </ul>
    <p><strong>Note:</strong> If download links have expired, contact the DevSecOps team for archived reports.</p>

    <div class="summary">
    <h3>📞 Container Security Resources</h3>
    <p><strong>Security Hub Console:</strong> <a href="https://console.aws.amazon.com/securityhub/">https://console.aws.amazon.com/securityhub/</a></p>
    <p><strong>Inspector Console:</strong> <a href="https://console.aws.amazon.com/inspector/">https://console.aws.amazon.com/inspector/</a></p>
    <p><strong>ECR Console:</strong> <a href="https://console.aws.amazon.com/ecr/">https://console.aws.amazon.com/ecr/</a></p>
    <p><strong>Container Security Guide:</strong> <a href="https://docs.aws.amazon.com/AmazonECR/latest/userguide/image-scanning.html">ECR Image Scanning Documentation</a></p>
    </div></body></html>"""
        
        return html_content

    def export_and_generate_csvs(self, consolidated_df, bucket_name=None):
        """Export both detailed and summary CSV reports."""
        # Detailed CSV
        try:
            filters = {
                'ResourceType': [{'Value': 'AwsEcrContainerImage', 'Comparison': 'EQUALS'}],
                'ProductName': [{'Value': 'Inspector', 'Comparison': 'EQUALS'}],
                'Type': [{'Value': 'Software and Configuration Checks/Vulnerabilities/CVE', 'Comparison': 'EQUALS'}],
                'RecordState': [{'Value': 'ACTIVE', 'Comparison': 'EQUALS'}]
            }
            
            findings = []
            paginator = self.securityhub_client.get_paginator('get_findings')
            for page in paginator.paginate(Filters=filters):
                findings.extend(page['Findings'])
            
            if not findings:
                detailed_csv = "No active ECR vulnerability findings found"
                detailed_s3_key = None
            else:
                df = self.process_findings_data(findings)
                detailed_csv = df.to_csv(index=False)
                detailed_s3_key = None
                if bucket_name:
                    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
                    detailed_s3_key = f"security-reports/ecr_vulnerabilities_{timestamp}.csv"
                    self.s3_client.put_object(Bucket=bucket_name, Key=detailed_s3_key, Body=detailed_csv.encode('utf-8'), ContentType='text/csv', ServerSideEncryption='AES256')
                    logger.info(f"Detailed CSV backed up to S3: s3://{bucket_name}/{detailed_s3_key}")
        except Exception as e:
            logger.error(f"Error generating detailed CSV: {e}")
            detailed_csv, detailed_s3_key = "Error generating detailed CSV", None
        
        # Summary CSV
        try:
            if consolidated_df.empty:
                summary_csv = "No vulnerability findings available for summary"
                summary_s3_key = None
            else:
                summary_data = []
                for repo_name, repo_group in consolidated_df.groupby('image_repository'):
                    if repo_name and str(repo_name) != 'nan' and repo_name != 'UNKNOWN-REPO':
                        severity_counts = repo_group['severity_label'].value_counts()
                        critical_count = severity_counts.get('CRITICAL', 0)
                        high_count = severity_counts.get('HIGH', 0)
                        medium_count = severity_counts.get('MEDIUM', 0)
                        
                        priority = "🚨 CRITICAL" if critical_count > 0 else "⚠️ HIGH" if high_count > 0 else "📋 MEDIUM" if medium_count > 0 else "📝 LOW"
                        risk_score = (critical_count * 10) + (high_count * 5) + (medium_count * 2)
                        
                        summary_data.append({
                            'repository_name': repo_name, 'total_vulnerabilities': len(repo_group),
                            'unique_cves': repo_group['cve_id'].nunique(), 'critical_count': critical_count,
                            'high_count': high_count, 'medium_count': medium_count, 'priority': priority,
                            'risk_score': risk_score, 'last_updated': repo_group['updated_at'].max().strftime('%Y-%m-%d') if 'updated_at' in repo_group.columns else 'Unknown'
                        })
                
                summary_df = pd.DataFrame(summary_data).sort_values('risk_score', ascending=False)
                summary_csv = summary_df.to_csv(index=False)
                summary_s3_key = None
                if bucket_name:
                    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
                    summary_s3_key = f"security-reports/ecr_summary_{timestamp}.csv"
                    self.s3_client.put_object(Bucket=bucket_name, Key=summary_s3_key, Body=summary_csv.encode('utf-8'), ContentType='text/csv', ServerSideEncryption='AES256')
                    logger.info(f"Summary CSV backed up to S3: s3://{bucket_name}/{summary_s3_key}")
        except Exception as e:
            logger.error(f"Error generating summary CSV: {e}")
            summary_csv, summary_s3_key = "Error generating summary CSV", None
        
        return (detailed_csv, detailed_s3_key), (summary_csv, summary_s3_key)

    def send_sns_report(self, summary, backup_info=None):
        """Send report summary via SNS."""
        try:
            critical_count = summary['severity_breakdown'].get('CRITICAL', 0)
            high_count = summary['severity_breakdown'].get('HIGH', 0)
            
            # Get URL expiration from environment (default 7 days, max 7 days for security)
            url_expiry_days = min(int(os.environ.get('REPORT_URL_EXPIRY_DAYS', '7')), 7)
            url_expiry_seconds = url_expiry_days * 24 * 60 * 60  # Convert to seconds
            
            # Get environment prefix for subject line
            environment = os.environ.get('ENVIRONMENT', '')
            env_prefix = f"[{environment}] " if environment else ""
            sns_subject = f"{env_prefix}ECR Vulnerability Report - {summary['total_findings']} findings ({critical_count} critical)"
            
            message = f"🐳 ECR Vulnerability Report - {datetime.now().strftime('%Y-%m-%d')}\n\n"
            
            # Enhanced summary with container usage data
            if summary.get('container_usage_available', False):
                message += f"📊 SUMMARY (Enhanced with Inspector Container Mapping)\n"
                message += f"• Active Images: {summary['total_active_images']} (in use)\n"
                message += f"• Inactive Images: {summary.get('total_inactive_images', 0)} (not in use)\n"
                message += f"• Usage Rate: {summary.get('active_image_percentage', 0)}%\n"
            else:
                message += f"📊 SUMMARY\n"
                message += f"• Scanned Images: {summary.get('total_scanned_images', summary['total_active_images'])}\n"
            message += f"• Vulnerabilities: {summary['total_findings']}\n"
            message += f"• Unique CVEs: {summary['total_unique_cves']}\n"
            message += f"• Critical: {critical_count} | High: {high_count}\n"
            message += f"• Accounts: {summary['accounts_affected']}\n\n"
            
            message += "🏆 TOP REPOSITORIES\n"
            for repo_name, unique_cves in list(summary['top_repositories'].items())[:3]:
                if repo_name and str(repo_name) != 'nan':
                    message += f"• {repo_name}: {unique_cves} CVEs\n"
            
            if backup_info and any(backup_info.values()):
                # Dynamic expiration message
                expiry_text = f"{url_expiry_days} day{'s' if url_expiry_days != 1 else ''}"
                message += f"\n💾 DOWNLOAD REPORTS (Links expire in {expiry_text})\n\n"
                
                if backup_info.get('html_s3_key'):
                    html_url = self.s3_client.generate_presigned_url('get_object', Params={'Bucket': backup_info.get('bucket_name'), 'Key': backup_info['html_s3_key']}, ExpiresIn=url_expiry_seconds)
                    message += f"📄 Complete HTML Report\n{html_url}\n\n"
                
                if backup_info.get('detailed_csv_s3_key'):
                    detailed_url = self.s3_client.generate_presigned_url('get_object', Params={'Bucket': backup_info.get('bucket_name'), 'Key': backup_info['detailed_csv_s3_key']}, ExpiresIn=url_expiry_seconds)
                    message += f"📊 Detailed Vulnerability CSV\n{detailed_url}\n\n"
                
                if backup_info.get('summary_csv_s3_key'):
                    summary_url = self.s3_client.generate_presigned_url('get_object', Params={'Bucket': backup_info.get('bucket_name'), 'Key': backup_info['summary_csv_s3_key']}, ExpiresIn=url_expiry_seconds)
                    message += f"📋 Repository Summary CSV\n{summary_url}\n\n"
                
                # Add note about contacting team after expiration
                if url_expiry_days < 7:
                    message += f"⚠️ NOTE: Short expiration set ({expiry_text})\n"
                message += f"📞 Contact DevSecOps team for archived reports after expiration\n\n"
            
            message += f"📞 Console: https://console.aws.amazon.com/securityhub/"
            
            response = self.sns_client.publish(TopicArn=self.sns_topic_arn, Subject=sns_subject, Message=message)
            logger.info(f"SNS sent - MessageId: {response['MessageId']}")
            logger.info(f"Subject: {sns_subject}")
            logger.info(f"Report URLs set to expire in {expiry_text}")
            
        except ClientError as e:
            logger.error(f"SNS error: {e}")
            raise
    
    def generate_weekly_report(self, s3_bucket=None, days_back=7):
        """Generate and send weekly ECR vulnerability report."""
        try:
            logger.info(f"Generating ECR report (last {days_back} days)...")
            
            # Try Inspector first for enhanced container usage data, fallback to Security Hub
            logger.info("Attempting to use Amazon Inspector for enhanced container usage data...")
            findings = self.get_ecr_findings_from_inspector(days_back)
            
            # Check if we got Inspector data by looking for Inspector-specific fields
            if findings and any('resources' in finding and 
                              any(res.get('details', {}).get('ecrContainerImage', {}).get('inUseCount') is not None 
                                  for res in finding.get('resources', []))
                              for finding in findings):
                logger.info("✅ Using Inspector data with container usage information")
                df = self.process_inspector_findings_data(findings)
            else:
                logger.info("Using processed findings data (Security Hub format)")
                df = self.process_findings_data(findings)
            consolidated_df = self.consolidate_findings(df)
            summary = self.generate_summary_stats(consolidated_df)
            html_content = self.create_html_report(consolidated_df, summary)
            
            (detailed_csv, detailed_s3_key), (summary_csv, summary_s3_key) = self.export_and_generate_csvs(consolidated_df, s3_bucket)
            
            html_s3_key = None
            if s3_bucket:
                timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
                html_s3_key = f"security-reports/ecr_report_{timestamp}.html"
                self.s3_client.put_object(Bucket=s3_bucket, Key=html_s3_key, Body=html_content.encode('utf-8'), ContentType='text/html', ServerSideEncryption='AES256')
                logger.info(f"HTML backed up to S3: s3://{s3_bucket}/{html_s3_key}")
            
            backup_info = {'bucket_name': s3_bucket, 'detailed_csv_s3_key': detailed_s3_key, 'summary_csv_s3_key': summary_s3_key, 'html_s3_key': html_s3_key} if s3_bucket else None
            
            self.send_sns_report(summary, backup_info)
            logger.info("Report generated successfully")
            
        except Exception as e:
            logger.error(f"Report generation error: {e}")
            raise

def lambda_handler(event, context):
    """Lambda handler for ECR vulnerability reporting."""
    try:
        # Get configuration from environment variables
        sns_topic_arn = os.environ.get('SNS_TOPIC_ARN')
        s3_bucket = os.environ.get('S3_BUCKET')
        region = os.environ.get('AWS_REGION', 'ap-southeast-2')
        days_back = int(os.environ.get('REPORT_DAYS_BACK', '7'))
        environment = os.environ.get('ENVIRONMENT', '')
        
        if not sns_topic_arn:
            error_msg = "Missing SNS_TOPIC_ARN environment variable"
            logger.error(error_msg)
            return {
                'statusCode': 400,
                'body': json.dumps({'error': error_msg})
            }
        
        # Display URL expiry configuration
        url_expiry_days = min(int(os.environ.get('REPORT_URL_EXPIRY_DAYS', '7')), 7)
        expiry_text = f"{url_expiry_days} day{'s' if url_expiry_days != 1 else ''}"
        
        logger.info(f"Starting ECR report generation...")
        logger.info(f"SNS Topic: {sns_topic_arn}")
        logger.info(f"Environment: {environment or 'Not set'}")
        logger.info(f"S3 Bucket: {s3_bucket or 'Disabled'}")
        logger.info(f"Report URLs expire in: {expiry_text}")
        logger.info(f"Days back: {days_back}")
        
        if url_expiry_days < 7:
            logger.warning(f"Short expiration configured: {expiry_text}")
        
        generator = ECRVulnerabilityReportGenerator(region, sns_topic_arn)
        
        # Test connections
        try:
            generator.securityhub_client.describe_hub()
            logger.info("Security Hub connection verified")
        except ClientError as e:
            error_msg = f"Security Hub connection failed: {e}"
            logger.error(error_msg)
            return {
                'statusCode': 500,
                'body': json.dumps({'error': error_msg})
            }
        
        try:
            generator.sns_client.get_topic_attributes(TopicArn=sns_topic_arn)
            logger.info("SNS topic connection verified")
        except ClientError as e:
            error_msg = f"SNS topic connection failed: {e}"
            logger.error(error_msg)
            return {
                'statusCode': 500,
                'body': json.dumps({'error': error_msg})
            }
        
        if s3_bucket:
            try:
                generator.s3_client.head_bucket(Bucket=s3_bucket)
                logger.info("S3 bucket connection verified")
            except ClientError as e:
                logger.warning(f"S3 bucket access failed (backup disabled): {e}")
                s3_bucket = None
        
        # Generate the report
        generator.generate_weekly_report(s3_bucket, days_back)
        
        logger.info("ECR vulnerability report generated and sent successfully")
        
        return {
            'statusCode': 200,
            'body': json.dumps({
                'message': 'ECR vulnerability report generated successfully',
                'sns_topic': sns_topic_arn,
                'environment': environment,
                's3_bucket': s3_bucket,
                'url_expiry_days': url_expiry_days,
                'days_back': days_back
            })
        }
        
    except Exception as e:
        error_msg = f"Report generation error: {str(e)}"
        logger.error(error_msg)
        return {
            'statusCode': 500,
            'body': json.dumps({'error': error_msg})
        }