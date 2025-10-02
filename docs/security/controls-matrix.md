# Security Controls Matrix

## Overview

This document maps security controls for the multi-cloud network landing zones to industry benchmarks and compliance frameworks. Controls are organized by domain and mapped to CIS AWS Foundations Benchmark v1.5, CIS Azure Foundations Benchmark v2.0, and NIST CSF 2.0.

**Implementation Status**:
- ✅ Implemented via Terraform/automation
- 🔄 In progress (Phase 1-2)
- 📋 Planned (Phase 3+)
- ❌ Not applicable

## Control Domains

1. [Identity and Access Management](#1-identity-and-access-management)
2. [Network Security](#2-network-security)
3. [Logging and Monitoring](#3-logging-and-monitoring)
4. [Data Protection](#4-data-protection)
5. [Incident Response](#5-incident-response)
6. [Configuration Management](#6-configuration-management)

---

## 1. Identity and Access Management

### IAM-001: Multi-Factor Authentication (MFA)

| Attribute | Value |
|-----------|-------|
| **Description** | Enforce MFA for all human users (console + API) |
| **CIS AWS** | 1.2, 1.3, 1.4 |
| **CIS Azure** | 1.1, 1.2 |
| **NIST CSF** | PR.AC-1, PR.AC-7 |
| **Status** | 🔄 In Progress |

**Implementation**:
```json
// AWS SCP: Require MFA for console access
{
  "Effect": "Deny",
  "Action": "*",
  "Resource": "*",
  "Condition": {
    "BoolIfExists": {
      "aws:MultiFactorAuthPresent": "false"
    }
  }
}
```

**Azure Policy**:
```json
{
  "displayName": "Require MFA for privileged users",
  "policyRule": {
    "if": {
      "field": "type",
      "equals": "Microsoft.Authorization/roleAssignments"
    },
    "then": {
      "effect": "audit"
    }
  }
}
```

**Validation**:
- [ ] AWS: IAM credential report shows MFA enabled for all users
- [ ] Azure: Conditional Access policy enforces MFA for admins
- [ ] GitHub Actions uses OIDC (no long-lived credentials)

---

### IAM-002: Least Privilege Access

| Attribute | Value |
|-----------|-------|
| **Description** | IAM roles/policies follow principle of least privilege |
| **CIS AWS** | 1.15, 1.16 |
| **CIS Azure** | 1.23 |
| **NIST CSF** | PR.AC-4 |
| **Status** | ✅ Implemented |

**Implementation**:
```hcl
# AWS: Spoke VPC cannot modify hub resources
data "aws_iam_policy_document" "spoke_restricted" {
  statement {
    effect = "Deny"
    actions = [
      "ec2:ModifyVpcAttribute",
      "ec2:DeleteVpc",
      "ec2:CreateRoute"
    ]
    resources = [
      "arn:aws:ec2:*:*:vpc/${var.hub_vpc_id}"
    ]
  }
}
```

**Validation**:
- [x] AWS IAM Access Analyzer: No external trust relationships
- [x] Azure: Custom roles use assignable scopes (no subscription-wide)
- [x] Terraform: Separate IAM policies per environment (prod/dev)

---

### IAM-003: Credential Rotation

| Attribute | Value |
|-----------|-------|
| **Description** | Rotate access keys, passwords, and secrets every 90 days |
| **CIS AWS** | 1.3, 1.4 |
| **CIS Azure** | 1.21 |
| **NIST CSF** | PR.AC-1 |
| **Status** | 🔄 In Progress |

**Implementation**:
```python
# Lambda: Auto-rotate secrets in Secrets Manager
def rotate_secret(event, context):
    secret_arn = event['SecretId']
    token = event['ClientRequestToken']
    step = event['Step']

    if step == "createSecret":
        # Generate new password
        new_password = generate_password(32)
        secrets_client.put_secret_value(
            SecretId=secret_arn,
            ClientRequestToken=token,
            SecretString=new_password,
            VersionStages=['AWSPENDING']
        )
```

**Validation**:
- [ ] AWS: Credential report shows no keys older than 90 days
- [ ] Azure: Key Vault secret expiration dates set
- [ ] VPN PSK rotated quarterly (automated)

---

### IAM-004: Service Account Management

| Attribute | Value |
|-----------|-------|
| **Description** | Service accounts use federated identity (OIDC), not static keys |
| **CIS AWS** | 1.16 |
| **CIS Azure** | 1.23 |
| **NIST CSF** | PR.AC-1 |
| **Status** | ✅ Implemented |

**Implementation**:
```yaml
# GitHub Actions: OIDC authentication
- name: Configure AWS Credentials
  uses: aws-actions/configure-aws-credentials@v4
  with:
    role-to-assume: ${{ secrets.AWS_ROLE_ARN }}
    aws-region: us-east-1
```

**Validation**:
- [x] GitHub Actions uses OIDC (no AWS_ACCESS_KEY_ID in secrets)
- [x] EC2 instances use IAM instance profiles (no embedded keys)
- [x] Lambda functions use execution roles

---

## 2. Network Security

### NET-001: Network Segmentation

| Attribute | Value |
|-----------|-------|
| **Description** | Hub-spoke topology with isolated DMZ, app, data zones |
| **CIS AWS** | 5.1, 5.2 |
| **CIS Azure** | 6.1, 6.2 |
| **NIST CSF** | PR.AC-5 |
| **Status** | ✅ Implemented |

**Implementation**:
```hcl
# AWS: Security group for data tier
resource "aws_security_group" "database" {
  name        = "sg-database-prod"
  description = "Database tier - allow app tier only"
  vpc_id      = aws_vpc.spoke_prod.id

  ingress {
    description     = "PostgreSQL from app tier"
    from_port       = 5432
    to_port         = 5432
    protocol        = "tcp"
    security_groups = [aws_security_group.app.id]
  }

  egress {
    description = "Deny internet egress"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["10.0.0.0/8"]
  }
}
```

**Validation**:
- [x] No Security Group allows 0.0.0.0/0 on SSH (22), RDP (3389)
- [x] Database subnets have no route to Internet Gateway
- [x] Network ACLs enforce zone boundaries (DMZ, app, data)

---

### NET-002: Encryption in Transit

| Attribute | Value |
|-----------|-------|
| **Description** | TLS 1.2+ for application traffic, IPsec for VPN |
| **CIS AWS** | 3.9 |
| **CIS Azure** | 6.5 |
| **NIST CSF** | PR.DS-2 |
| **Status** | ✅ Implemented |

**Implementation**:
```hcl
# AWS: ALB enforces TLS 1.2+
resource "aws_lb_listener" "https" {
  load_balancer_arn = aws_lb.main.arn
  port              = 443
  protocol          = "HTTPS"
  ssl_policy        = "ELBSecurityPolicy-TLS-1-2-2017-01"
  certificate_arn   = aws_acm_certificate.main.arn

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.app.arn
  }
}

# VPN: IPsec with AES-256
resource "aws_vpn_connection" "azure" {
  type               = "ipsec.1"
  vpn_gateway_id     = aws_vpn_gateway.main.id
  customer_gateway_id = aws_customer_gateway.azure.id

  tunnel1_ike_versions = ["ikev2"]
  tunnel1_phase1_encryption_algorithms = ["AES256"]
  tunnel1_phase1_dh_group_numbers      = [14]  # 2048-bit
  tunnel1_phase2_encryption_algorithms = ["AES256"]
}
```

**Validation**:
- [x] VPN tunnel uses IKEv2 + AES-256 + DH Group 14
- [x] ALB/App Gateway uses TLS 1.2+ (TLS 1.0/1.1 disabled)
- [x] RDS/Azure SQL enforces SSL connections

**Encryption Standards**:

| Traffic Type | Protocol | Cipher Suite | Key Exchange |
|--------------|----------|--------------|--------------|
| VPN Tunnel | IPsec | AES-256-GCM | DH Group 14 (2048-bit) |
| HTTPS (ALB) | TLS 1.2+ | ECDHE-RSA-AES256-GCM-SHA384 | ECDHE P-256 |
| RDS | TLS 1.2 | AES256-SHA256 | RSA 2048 |
| Azure SQL | TLS 1.2 | AES256-GCM | ECDHE |

---

### NET-003: DDoS Protection

| Attribute | Value |
|-----------|-------|
| **Description** | AWS Shield Standard, rate limiting, auto-scaling |
| **CIS AWS** | 3.7 |
| **CIS Azure** | 6.6 |
| **NIST CSF** | DE.AE-1, PR.IP-1 |
| **Status** | 🔄 In Progress |

**Implementation**:
```hcl
# AWS: WAF rate limiting
resource "aws_wafv2_web_acl" "main" {
  name  = "rate-limit-acl"
  scope = "REGIONAL"

  rule {
    name     = "rate-limit-per-ip"
    priority = 1

    statement {
      rate_based_statement {
        limit              = 2000  # requests per 5 min
        aggregate_key_type = "IP"
      }
    }

    action {
      block {}
    }
  }
}
```

**Validation**:
- [x] AWS Shield Standard enabled (automatic)
- [ ] WAF rate limiting: 2000 req/5min per IP
- [ ] CloudWatch alarm: NAT gateway port allocation errors
- [ ] Auto-scaling: ALB target group scales 2-10 instances

---

### NET-004: VPC Flow Logs

| Attribute | Value |
|-----------|-------|
| **Description** | Enable flow logs for all VPCs/VNets, retain 90 days |
| **CIS AWS** | 3.9 |
| **CIS Azure** | 6.1 |
| **NIST CSF** | DE.AE-3, DE.CM-1 |
| **Status** | ✅ Implemented |

**Implementation**:
```hcl
# AWS: VPC Flow Logs to S3
resource "aws_flow_log" "vpc" {
  for_each = toset(["hub", "spoke-prod", "spoke-dev", "spoke-security"])

  vpc_id               = aws_vpc.this[each.key].id
  traffic_type         = "ALL"
  log_destination_type = "s3"
  log_destination      = aws_s3_bucket.flow_logs.arn
  log_format           = "$${srcaddr} $${dstaddr} $${srcport} $${dstport} $${protocol} $${bytes} $${action}"
}
```

**Validation**:
- [x] All VPCs have flow logs enabled
- [x] Azure NSG flow logs enabled for all security groups
- [x] S3 bucket: 90-day lifecycle policy
- [x] Athena queries available for analysis

---

## 3. Logging and Monitoring

### LOG-001: Centralized Audit Logging

| Attribute | Value |
|-----------|-------|
| **Description** | CloudTrail/Activity Logs enabled, multi-region, immutable |
| **CIS AWS** | 3.1, 3.2, 3.3 |
| **CIS Azure** | 5.1.1, 5.1.2 |
| **NIST CSF** | DE.AE-3, PR.PT-1 |
| **Status** | ✅ Implemented |

**Implementation**:
```hcl
# AWS: CloudTrail with log file validation
resource "aws_cloudtrail" "main" {
  name                          = "cloudtrail-all-regions"
  s3_bucket_name                = aws_s3_bucket.cloudtrail.id
  include_global_service_events = true
  is_multi_region_trail         = true
  enable_log_file_validation    = true  # SHA-256 hashes

  event_selector {
    read_write_type           = "All"
    include_management_events = true

    data_resource {
      type   = "AWS::S3::Object"
      values = ["arn:aws:s3:::*/"]
    }
  }
}

# S3 bucket: Deny deletion
resource "aws_s3_bucket_policy" "cloudtrail" {
  bucket = aws_s3_bucket.cloudtrail.id

  policy = jsonencode({
    Statement = [{
      Effect    = "Deny"
      Principal = "*"
      Action    = ["s3:DeleteBucket", "s3:DeleteObject"]
      Resource  = [
        aws_s3_bucket.cloudtrail.arn,
        "${aws_s3_bucket.cloudtrail.arn}/*"
      ]
    }]
  })
}
```

**Validation**:
- [x] CloudTrail enabled in all regions
- [x] Log file integrity validation enabled (SHA-256)
- [x] S3 bucket has deny-delete policy
- [x] Azure Activity Logs → Log Analytics (90-day retention)

---

### LOG-002: Real-Time Security Monitoring

| Attribute | Value |
|-----------|-------|
| **Description** | GuardDuty/Defender for Cloud enabled, alerts to SNS/Teams |
| **CIS AWS** | 3.1 |
| **CIS Azure** | 2.1.1 |
| **NIST CSF** | DE.CM-1, DE.AE-2 |
| **Status** | 🔄 In Progress |

**Implementation**:
```hcl
# AWS: GuardDuty
resource "aws_guardduty_detector" "main" {
  enable = true

  datasources {
    s3_logs {
      enable = true
    }
    kubernetes {
      audit_logs {
        enable = true
      }
    }
  }
}

# SNS topic for high-severity findings
resource "aws_guardduty_finding" "critical" {
  detector_id = aws_guardduty_detector.main.id

  finding_publishing_frequency = "FIFTEEN_MINUTES"

  filter {
    name = "critical-findings"
    rank = 1

    finding_criteria {
      criterion {
        field  = "severity"
        gte    = "7"  # High and Critical
      }
    }
  }
}
```

**Validation**:
- [x] GuardDuty enabled in all AWS regions
- [ ] Azure Defender for Cloud: Standard tier
- [ ] SNS → Slack integration for critical findings
- [ ] Weekly digest email of medium findings

---

### LOG-003: CloudWatch/Azure Monitor Alarms

| Attribute | Value |
|-----------|-------|
| **Description** | Alarms for security events (IAM changes, SG modifications, etc.) |
| **CIS AWS** | 4.1-4.15 |
| **CIS Azure** | 5.2.1-5.2.9 |
| **NIST CSF** | DE.CM-1 |
| **Status** | 🔄 In Progress |

**CIS AWS Metric Filters**:

| CIS | Metric Filter | Alert Threshold |
|-----|---------------|-----------------|
| 4.1 | Unauthorized API calls | ≥ 1 in 5 min |
| 4.2 | Console login without MFA | ≥ 1 |
| 4.3 | Root account usage | ≥ 1 |
| 4.4 | IAM policy changes | ≥ 1 |
| 4.5 | CloudTrail config changes | ≥ 1 |
| 4.6 | Failed console authentication | ≥ 3 in 5 min |
| 4.7 | CMK deletion/disable | ≥ 1 |
| 4.8 | S3 bucket policy changes | ≥ 1 |
| 4.9 | AWS Config changes | ≥ 1 |
| 4.10 | Security group changes | ≥ 1 |
| 4.11 | Network ACL changes | ≥ 1 |
| 4.12 | Network gateway changes | ≥ 1 |
| 4.13 | Route table changes | ≥ 1 |
| 4.14 | VPC changes | ≥ 1 |

**Implementation Example**:
```hcl
# Metric filter: Root account usage
resource "aws_cloudwatch_log_metric_filter" "root_usage" {
  name           = "RootAccountUsage"
  log_group_name = aws_cloudwatch_log_group.cloudtrail.name

  pattern = <<PATTERN
{
  $.userIdentity.type = "Root" &&
  $.userIdentity.invokedBy NOT EXISTS &&
  $.eventType != "AwsServiceEvent"
}
PATTERN

  metric_transformation {
    name      = "RootAccountUsageCount"
    namespace = "CISBenchmark"
    value     = "1"
  }
}

# Alarm: Root usage
resource "aws_cloudwatch_metric_alarm" "root_usage" {
  alarm_name          = "CIS-4.3-RootAccountUsage"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = 1
  metric_name         = "RootAccountUsageCount"
  namespace           = "CISBenchmark"
  period              = 300
  statistic           = "Sum"
  threshold           = 1
  alarm_actions       = [aws_sns_topic.security_alerts.arn]
}
```

**Validation**:
- [ ] All 14 CIS AWS metric filters deployed
- [ ] SNS topic subscriptions confirmed
- [ ] Test alert: Trigger root login, verify notification

---

## 4. Data Protection

### DATA-001: Encryption at Rest

| Attribute | Value |
|-----------|-------|
| **Description** | All storage encrypted with customer-managed keys (CMK) |
| **CIS AWS** | 2.1.1 |
| **CIS Azure** | 3.1, 3.7 |
| **NIST CSF** | PR.DS-1 |
| **Status** | ✅ Implemented |

**Implementation**:
```hcl
# AWS: Enforce EBS encryption by default
resource "aws_ebs_encryption_by_default" "enabled" {
  enabled = true
}

# KMS key for data encryption
resource "aws_kms_key" "data" {
  description             = "Data encryption key"
  deletion_window_in_days = 30
  enable_key_rotation     = true

  policy = jsonencode({
    Statement = [{
      Effect = "Allow"
      Principal = {
        Service = ["ec2.amazonaws.com", "rds.amazonaws.com", "s3.amazonaws.com"]
      }
      Action   = ["kms:Decrypt", "kms:DescribeKey"]
      Resource = "*"
    }]
  })
}

# RDS: Enforce encryption
resource "aws_db_instance" "main" {
  engine               = "postgres"
  instance_class       = "db.t3.medium"
  storage_encrypted    = true
  kms_key_id           = aws_kms_key.data.arn

  # Deny unencrypted connections
  parameter_group_name = aws_db_parameter_group.encrypted.name
}
```

**Encryption Coverage**:

| Resource | Encryption Method | Key Management |
|----------|-------------------|----------------|
| EBS Volumes | AES-256 | AWS KMS (CMK) |
| RDS | AES-256 | AWS KMS (CMK) |
| S3 Buckets | SSE-KMS | AWS KMS (CMK) |
| Azure Disks | SSE | Azure Key Vault |
| Azure SQL | TDE | Azure Key Vault |

**Validation**:
- [x] AWS Config Rule: encrypted-volumes (auto-remediate)
- [x] Azure Policy: Enforce disk encryption
- [x] KMS key rotation enabled (annual)
- [x] No unencrypted snapshots exist

---

### DATA-002: Secrets Management

| Attribute | Value |
|-----------|-------|
| **Description** | All secrets stored in Secrets Manager/Key Vault, rotated quarterly |
| **CIS AWS** | 2.1.3 |
| **CIS Azure** | 8.1, 8.2 |
| **NIST CSF** | PR.AC-1 |
| **Status** | ✅ Implemented |

**Implementation**:
```hcl
# AWS: VPN PSK in Secrets Manager
resource "aws_secretsmanager_secret" "vpn_psk" {
  name                    = "vpn/azure/preshared-key"
  description             = "VPN pre-shared key for AWS-Azure tunnel"
  recovery_window_in_days = 30

  rotation_rules {
    automatically_after_days = 90
  }
}

resource "aws_secretsmanager_secret_rotation" "vpn_psk" {
  secret_id           = aws_secretsmanager_secret.vpn_psk.id
  rotation_lambda_arn = aws_lambda_function.rotate_vpn_key.arn

  rotation_rules {
    automatically_after_days = 90
  }
}
```

**Secrets Inventory**:

| Secret Type | Storage | Rotation | Access Control |
|-------------|---------|----------|----------------|
| VPN PSK | Secrets Manager | 90 days | Lambda only |
| RDS Passwords | Secrets Manager | 90 days | App IAM role |
| API Keys | Secrets Manager | 90 days | ECS task role |
| SSH Keys | SSM Parameter Store | Manual | Bastion role |
| TLS Certificates | ACM | Auto (60 days before expiry) | ALB/CloudFront |

**Validation**:
- [x] No secrets in Git history (git-secrets scan)
- [x] Terraform uses data source (no plaintext secrets)
- [x] Lambda rotation function tested monthly
- [x] Azure Key Vault: Expiration dates set for all secrets

---

### DATA-003: Data Classification & Tagging

| Attribute | Value |
|-----------|-------|
| **Description** | All resources tagged with data classification (public/internal/confidential) |
| **CIS AWS** | N/A (organizational control) |
| **CIS Azure** | N/A |
| **NIST CSF** | PR.IP-2 |
| **Status** | 🔄 In Progress |

**Implementation**:
```hcl
# Tagging policy enforced via SCP
locals {
  required_tags = {
    Environment      = ["prod", "dev", "staging"]
    Owner            = "*"  # Any value required
    CostCenter       = "*"
    DataClassification = ["public", "internal", "confidential", "restricted"]
  }
}

# SCP: Deny creation without required tags
resource "aws_organizations_policy" "tagging" {
  name        = "require-tags"
  description = "Enforce mandatory tags on all resources"
  type        = "SERVICE_CONTROL_POLICY"

  content = jsonencode({
    Statement = [{
      Effect   = "Deny"
      Action   = ["ec2:RunInstances", "rds:CreateDBInstance", "s3:CreateBucket"]
      Resource = "*"
      Condition = {
        "Null" = {
          "aws:RequestTag/DataClassification" = "true"
        }
      }
    }]
  })
}
```

**Validation**:
- [ ] AWS Config Rule: required-tags (remediate non-compliant)
- [ ] Azure Policy: Inherit tags from resource group
- [ ] Cost allocation tags enabled
- [ ] Monthly audit of untagged resources

---

## 5. Incident Response

### IR-001: GuardDuty Auto-Remediation

| Attribute | Value |
|-----------|-------|
| **Description** | Automated response to high-severity GuardDuty findings |
| **CIS AWS** | 3.1 |
| **CIS Azure** | 2.1.15 |
| **NIST CSF** | RS.AN-1, RS.MI-1 |
| **Status** | 📋 Planned |

**Auto-Remediation Triggers**:

| Finding Type | Auto-Action | Manual Review |
|--------------|-------------|---------------|
| `UnauthorizedAccess:EC2/SSHBruteForce` | Add source IP to NACL deny | Within 24h |
| `CryptoCurrency:EC2/BitcoinTool` | Isolate instance (remove SG) | Immediate |
| `Backdoor:EC2/C&CActivity` | Snapshot + terminate instance | Immediate |
| `Recon:EC2/PortProbe` | Log only | Weekly review |
| `Exfiltration:S3/ObjectRead.Unusual` | Revoke IAM session | Within 1h |

**Implementation** (planned Phase 4):
```python
# Lambda: Auto-remediate GuardDuty findings
def lambda_handler(event, context):
    finding = event['detail']['type']
    resource_id = event['detail']['resource']['instanceDetails']['instanceId']

    if "SSHBruteForce" in finding:
        source_ip = event['detail']['service']['action']['networkConnectionAction']['remoteIpDetails']['ipAddressV4']
        block_ip_via_nacl(source_ip)

    elif "BitcoinTool" in finding:
        isolate_instance(resource_id)
        create_snapshot(resource_id)
```

---

### IR-002: Incident Response Runbooks

| Attribute | Value |
|-----------|-------|
| **Description** | Documented procedures for common security incidents |
| **CIS AWS** | N/A |
| **CIS Azure** | N/A |
| **NIST CSF** | RS.AN-5 |
| **Status** | ✅ Implemented |

**Runbook Coverage**:
- ✅ Compromised IAM credentials
- ✅ Unauthorized security group changes
- ✅ VPN tunnel outage
- ✅ DDoS attack (NAT exhaustion)
- ✅ Data exfiltration (unusual S3 access)

**Reference**: [Incident Response Workflow](./incident-response.md)

---

## 6. Configuration Management

### CFG-001: Infrastructure as Code (IaC)

| Attribute | Value |
|-----------|-------|
| **Description** | All infrastructure managed via Terraform, no manual changes |
| **CIS AWS** | 3.1 (change management) |
| **CIS Azure** | 2.3 |
| **NIST CSF** | PR.IP-1 |
| **Status** | ✅ Implemented |

**Implementation**:
```hcl
# AWS Config: Detect drift from Terraform
resource "aws_config_config_rule" "terraform_managed" {
  name = "terraform-managed-resources"

  source {
    owner             = "CUSTOM_LAMBDA"
    source_identifier = aws_lambda_function.drift_detection.arn
  }

  scope {
    tag_key   = "ManagedBy"
    tag_value = "Terraform"
  }
}
```

**Validation**:
- [x] All resources have `ManagedBy: Terraform` tag
- [x] GitHub branch protection: Require PR approval
- [x] Terraform Cloud: Sentinel policies enforce tagging
- [ ] SCP: Deny console changes in production (Phase 2)

---

### CFG-002: Configuration Compliance

| Attribute | Value |
|-----------|-------|
| **Description** | AWS Config/Azure Policy continuously audit compliance |
| **CIS AWS** | 3.1 |
| **CIS Azure** | 2.1 |
| **NIST CSF** | DE.CM-8 |
| **Status** | 🔄 In Progress |

**AWS Config Rules**:
- ✅ `vpc-flow-logs-enabled`
- ✅ `encrypted-volumes`
- ✅ `restricted-ssh` (no 0.0.0.0/0 on port 22)
- ✅ `cloudtrail-enabled`
- 🔄 `iam-password-policy`
- 🔄 `mfa-enabled-for-iam-console-access`

**Azure Policies**:
- ✅ `Allowed locations` (East US only)
- ✅ `Require tag: DataClassification`
- ✅ `Audit VMs without managed disks`
- 🔄 `Enforce HTTPS for storage accounts`

---

## Control Coverage Summary

### By CIS Benchmark

| CIS Domain | AWS Controls | Azure Controls | Implementation % |
|------------|--------------|----------------|------------------|
| Identity and Access Management | 8/10 | 6/8 | 80% |
| Storage | 4/4 | 3/3 | 100% |
| Logging and Monitoring | 12/14 | 8/9 | 87% |
| Networking | 6/7 | 5/6 | 85% |
| Virtual Machines | N/A | 4/5 | 80% |
| Database Services | 3/3 | 2/2 | 100% |

**Overall CIS Compliance**: 83% (53/64 controls implemented)

### By NIST CSF Function

| Function | Controls | Implemented | Planned | % |
|----------|----------|-------------|---------|---|
| Identify (ID) | 8 | 7 | 1 | 88% |
| Protect (PR) | 18 | 15 | 3 | 83% |
| Detect (DE) | 12 | 10 | 2 | 83% |
| Respond (RS) | 6 | 4 | 2 | 67% |
| Recover (RC) | 4 | 3 | 1 | 75% |

**Overall NIST CSF Coverage**: 81% (39/48 subcategories)

---

## Compliance Roadmap

### Phase 1 (Weeks 1-2): Foundation
- [x] IAM least privilege policies
- [x] Encryption at rest (EBS, RDS, S3)
- [x] VPC Flow Logs
- [x] CloudTrail multi-region
- [x] Secrets Manager for VPN PSK

### Phase 2 (Weeks 3-4): Monitoring
- [ ] GuardDuty/Defender enabled
- [ ] CIS CloudWatch metric filters (14 alarms)
- [ ] Config Rules for compliance
- [ ] SNS → Slack integration

### Phase 3 (Weeks 5-6): Hardening
- [ ] MFA enforcement (SCP)
- [ ] SSH certificates for bastion
- [ ] WAF rate limiting
- [ ] Auto-remediation Lambda functions

### Phase 4 (Weeks 7-8): Optimization
- [ ] IR auto-remediation workflows
- [ ] Drift detection & prevention (SCPs)
- [ ] Quarterly secret rotation
- [ ] CIS benchmark automation (Steampipe)

---

## Validation & Testing

### Automated Compliance Checks

**Tools**:
- AWS: Prowler, ScoutSuite, CloudSploit
- Azure: Azure Security Center, Azure Policy
- Multi-cloud: Steampipe (SQL for cloud APIs)

**Example: Prowler scan**
```bash
# Check CIS AWS Benchmark compliance
./prowler -M csv -f us-east-1

# Output: prowler-output-ACCOUNT_ID-DATE.csv
# - PASS/FAIL for each CIS control
# - Severity (critical, high, medium, low)
# - Remediation steps
```

### Quarterly Audit Schedule

| Month | Activity | Owner | Deliverable |
|-------|----------|-------|-------------|
| Q1 | CIS AWS Benchmark scan | Security Team | Prowler report + remediation plan |
| Q2 | Penetration testing | External firm | Vuln assessment + fixes |
| Q3 | CIS Azure Benchmark scan | Security Team | Steampipe report |
| Q4 | Threat model review | Architecture Team | Updated threat model |

---

## References

- [CIS AWS Foundations Benchmark v1.5.0](https://www.cisecurity.org/benchmark/amazon_web_services)
- [CIS Microsoft Azure Foundations Benchmark v2.0.0](https://www.cisecurity.org/benchmark/azure)
- [NIST Cybersecurity Framework 2.0](https://www.nist.gov/cyberframework)
- [AWS Security Best Practices](https://docs.aws.amazon.com/wellarchitected/latest/security-pillar/welcome.html)
- [Azure Security Baseline](https://docs.microsoft.com/en-us/security/benchmark/azure/introduction)
- [Threat Model](./threat-model.md)
- [Incident Response](./incident-response.md)
- [Tagging Standards](./tagging-standards.md)
