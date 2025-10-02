# Tagging and Labeling Standards

## Executive Summary

This document defines the mandatory tagging taxonomy for all AWS and Azure resources. Tags support cost allocation, compliance tracking, automation, and operational management. Non-compliant resources will be flagged for remediation or deletion.

**Enforcement**: Service Control Policies (AWS), Azure Policy (Azure), Terraform validation

## Tagging Taxonomy

### Mandatory Tags (Required for All Resources)

| Tag Key | Allowed Values | Example | Purpose |
|---------|----------------|---------|---------|
| `Environment` | `prod`, `dev`, `staging`, `sandbox` | `prod` | Lifecycle management, cost allocation |
| `Owner` | Email or team name | `platform-team@company.com` | Accountability, contact for issues |
| `CostCenter` | Department code | `ENG-001`, `SEC-002` | Chargeback, budget tracking |
| `ManagedBy` | `Terraform`, `Manual`, `CloudFormation` | `Terraform` | Change management, drift detection |
| `DataClassification` | `public`, `internal`, `confidential`, `restricted` | `confidential` | Security controls, compliance |

### Recommended Tags (Optional but Encouraged)

| Tag Key | Allowed Values | Example | Purpose |
|---------|----------------|---------|---------|
| `Project` | Project name | `cloud-netsec-blueprints` | Cost allocation by initiative |
| `Compliance` | `PCI`, `SOC2`, `HIPAA`, `None` | `SOC2` | Audit scoping |
| `BackupPolicy` | `daily`, `weekly`, `none` | `daily` | Automated backup scheduling |
| `AutoShutdown` | `true`, `false` | `true` | Dev environment cost optimization |
| `PatchGroup` | `critical`, `standard`, `test` | `critical` | Maintenance window scheduling |

### Auto-Applied Tags (Terraform)

| Tag Key | Source | Example | Purpose |
|---------|--------|---------|---------|
| `TerraformWorkspace` | `terraform.workspace` | `prod` | Track Terraform state |
| `GitRepo` | `var.git_repo` | `github.com/user/repo` | Source code traceability |
| `GitCommit` | `var.git_commit_sha` | `9e25fb3` | Deployment version tracking |
| `CreatedDate` | `timestamp()` | `2025-10-02T10:30:00Z` | Resource age tracking |

---

## Tag Enforcement

### AWS Service Control Policy (SCP)

**File**: `/policy/aws-scps/require-tags.json`

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "DenyCreateWithoutMandatoryTags",
      "Effect": "Deny",
      "Action": [
        "ec2:RunInstances",
        "ec2:CreateVolume",
        "ec2:CreateSnapshot",
        "rds:CreateDBInstance",
        "s3:CreateBucket",
        "elasticloadbalancing:CreateLoadBalancer"
      ],
      "Resource": "*",
      "Condition": {
        "Null": {
          "aws:RequestTag/Environment": "true"
        }
      }
    },
    {
      "Sid": "RequireValidEnvironmentTag",
      "Effect": "Deny",
      "Action": [
        "ec2:RunInstances",
        "rds:CreateDBInstance"
      ],
      "Resource": "*",
      "Condition": {
        "ForAnyValue:StringNotEquals": {
          "aws:RequestTag/Environment": [
            "prod",
            "dev",
            "staging",
            "sandbox"
          ]
        }
      }
    },
    {
      "Sid": "RequireCostCenterTag",
      "Effect": "Deny",
      "Action": [
        "ec2:RunInstances",
        "rds:CreateDBInstance"
      ],
      "Resource": "*",
      "Condition": {
        "Null": {
          "aws:RequestTag/CostCenter": "true"
        }
      }
    }
  ]
}
```

### Azure Policy

**File**: `/policy/azure-policy/require-tags.json`

```json
{
  "displayName": "Require mandatory tags on resources",
  "description": "Enforces existence of Environment, Owner, CostCenter tags",
  "mode": "Indexed",
  "policyRule": {
    "if": {
      "anyOf": [
        {
          "field": "tags['Environment']",
          "exists": "false"
        },
        {
          "field": "tags['Owner']",
          "exists": "false"
        },
        {
          "field": "tags['CostCenter']",
          "exists": "false"
        }
      ]
    },
    "then": {
      "effect": "deny"
    }
  }
}
```

### Terraform Validation

```hcl
# variables.tf: Define allowed values
variable "environment" {
  description = "Environment name"
  type        = string

  validation {
    condition     = contains(["prod", "dev", "staging", "sandbox"], var.environment)
    error_message = "Environment must be prod, dev, staging, or sandbox."
  }
}

# locals.tf: Define common tags
locals {
  common_tags = {
    Environment         = var.environment
    Owner               = var.owner_email
    CostCenter          = var.cost_center
    ManagedBy           = "Terraform"
    DataClassification  = var.data_classification
    TerraformWorkspace  = terraform.workspace
    GitRepo             = var.git_repo
    GitCommit           = var.git_commit_sha
    CreatedDate         = timestamp()
  }
}

# Apply tags to all resources
resource "aws_instance" "app" {
  ami           = data.aws_ami.ubuntu.id
  instance_type = "t3.medium"

  tags = merge(
    local.common_tags,
    {
      Name = "app-server-prod"
      Role = "application"
    }
  )
}
```

---

## Tag Value Standards

### Environment Tag

| Value | Description | Use Case |
|-------|-------------|----------|
| `prod` | Production workloads | Customer-facing applications, critical data |
| `staging` | Pre-production testing | Final QA before prod deployment |
| `dev` | Development environment | Feature development, integration testing |
| `sandbox` | Experimentation | Proof-of-concepts, temporary workloads |

**Naming Conventions**:
- VPC names: `{cloud}-{env}-vpc` (e.g., `aws-prod-vpc`)
- Instance names: `{app}-{env}-{az}` (e.g., `web-prod-1a`)

### Data Classification Tag

| Value | Description | Security Controls |
|-------|-------------|-------------------|
| `public` | Publicly accessible data | Basic encryption, public S3 allowed |
| `internal` | Internal company data | VPN required, encryption at rest |
| `confidential` | Sensitive business data | MFA required, encryption + DLP |
| `restricted` | Highly sensitive (PII, PHI) | Strict access controls, audit logging |

**Control Mapping**:

| Classification | Encryption | Access | Logging | Backup |
|----------------|------------|--------|---------|--------|
| Public | TLS in transit | IAM public read | Standard | Weekly |
| Internal | TLS + KMS at rest | IAM authenticated | Enhanced | Daily |
| Confidential | TLS 1.3 + CMK | MFA required | Real-time SIEM | Hourly |
| Restricted | TLS 1.3 + HSM | MFA + approval workflow | Immutable logs | Continuous (RPO < 1h) |

**Example**: S3 bucket with `DataClassification: restricted`
```hcl
resource "aws_s3_bucket" "pii_data" {
  bucket = "company-pii-prod"

  tags = merge(
    local.common_tags,
    {
      DataClassification = "restricted"
    }
  )
}

# Auto-apply security controls based on tag
resource "aws_s3_bucket_server_side_encryption_configuration" "pii" {
  count  = lookup(aws_s3_bucket.pii_data.tags, "DataClassification", "") == "restricted" ? 1 : 0
  bucket = aws_s3_bucket.pii_data.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.restricted_data.arn
    }
  }
}

# Deny public access for restricted data
resource "aws_s3_bucket_public_access_block" "pii" {
  count  = lookup(aws_s3_bucket.pii_data.tags, "DataClassification", "") == "restricted" ? 1 : 0
  bucket = aws_s3_bucket.pii_data.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}
```

### Cost Center Tag

**Format**: `{DEPT}-{NUMBER}` (e.g., `ENG-001`)

| Department Code | Description | Budget Owner |
|-----------------|-------------|--------------|
| `ENG-001` | Platform Engineering | VP Engineering |
| `SEC-001` | Security Operations | CISO |
| `DATA-001` | Data Analytics | CTO |
| `INFRA-001` | Infrastructure | VP Engineering |

**AWS Cost Allocation**:
1. Enable cost allocation tags in Billing console
2. Tag all resources with `CostCenter`
3. Use Cost Explorer to filter by tag
4. Export to S3 for chargeback reports

**Azure Cost Management**:
1. Tag resources with `CostCenter`
2. Use Cost Analysis → Group by: Tags
3. Create budgets per cost center
4. Set alerts at 80%, 100%, 120% of budget

---

## Cost Allocation Strategy

### Monthly Chargeback Process

**Step 1: Generate Cost Reports**

```bash
# AWS: Export cost report filtered by CostCenter tag
aws ce get-cost-and-usage \
  --time-period Start=2025-10-01,End=2025-10-31 \
  --granularity MONTHLY \
  --metrics BlendedCost \
  --group-by Type=TAG,Key=CostCenter \
  --output json > monthly-costs.json

# Azure: Export cost data
az costmanagement query \
  --type Usage \
  --timeframe MonthToDate \
  --dataset-grouping name=CostCenter type=Tag \
  --output table
```

**Step 2: Allocate Shared Costs**

| Resource | Cost | Allocation Method |
|----------|------|-------------------|
| VPN Gateway | $400/mo | Split by data transfer volume |
| NAT Gateway | $70/mo | Split equally across spoke environments |
| GuardDuty | $50/mo | Allocated to `SEC-001` |
| CloudTrail | $30/mo | Split by API call count per cost center |

**Step 3: Generate Invoice**

```csv
CostCenter,DirectCosts,SharedCosts,TotalCosts,Budget,Variance
ENG-001,$1200,$150,$1350,$1500,-10%
SEC-001,$800,$100,$900,$1000,-10%
DATA-001,$500,$50,$550,$600,-8%
```

### Cost Optimization by Tag

**Auto-Shutdown Dev Resources** (tagged `AutoShutdown: true`):

```python
# Lambda: Stop dev instances nightly
import boto3
ec2 = boto3.client('ec2')

def lambda_handler(event, context):
    # Find instances with AutoShutdown tag
    response = ec2.describe_instances(
        Filters=[
            {'Name': 'tag:AutoShutdown', 'Values': ['true']},
            {'Name': 'tag:Environment', 'Values': ['dev', 'sandbox']},
            {'Name': 'instance-state-name', 'Values': ['running']}
        ]
    )

    instance_ids = [i['InstanceId'] for r in response['Reservations'] for i in r['Instances']]

    if instance_ids:
        ec2.stop_instances(InstanceIds=instance_ids)
        print(f"Stopped {len(instance_ids)} instances: {instance_ids}")

    return {'statusCode': 200, 'body': f'Stopped {len(instance_ids)} instances'}
```

**Savings**: ~70% reduction in dev/sandbox compute costs

---

## Compliance Tracking

### Tagging for Compliance Audits

**Compliance Tag Values**:
- `PCI`: PCI-DSS scope (payment card data)
- `SOC2`: SOC 2 Type II audit scope
- `HIPAA`: HIPAA-regulated PHI
- `None`: Not in compliance scope

**Example: SOC 2 Audit Scope**

```hcl
# Tag resources in SOC 2 scope
resource "aws_instance" "app_prod" {
  tags = {
    Compliance = "SOC2"
    # ... other tags
  }
}

# Generate audit report
data "aws_instances" "soc2_scope" {
  filter {
    name   = "tag:Compliance"
    values = ["SOC2"]
  }
}

output "soc2_resources" {
  value = data.aws_instances.soc2_scope.ids
}
```

**Audit Queries**:

```sql
-- Athena: Find all SOC 2 resources
SELECT
  resource_id,
  resource_type,
  tags['Environment'] as environment,
  tags['DataClassification'] as classification
FROM cost_and_usage_report
WHERE tags['Compliance'] = 'SOC2'
  AND line_item_usage_start_date >= DATE '2025-01-01'
GROUP BY resource_id, resource_type, tags['Environment'], tags['DataClassification']
```

---

## Tag Governance

### Tag Review Schedule

| Frequency | Activity | Owner | Tool |
|-----------|----------|-------|------|
| Daily | Scan for untagged resources | Automation | AWS Config Rule |
| Weekly | Review new resources | Ops Team | Tag Editor |
| Monthly | Cost allocation accuracy | Finance | Cost Explorer |
| Quarterly | Compliance tag audit | Security | Prowler, Steampipe |

### Remediation Process

**Untagged Resources Workflow**:

1. **Detection**: AWS Config Rule `required-tags` flags non-compliant resource
2. **Notification**: SNS → Slack `#infrastructure` channel
3. **Grace Period**: 7 days to add tags
4. **Escalation**: Email to resource owner (from CloudTrail `userIdentity`)
5. **Auto-Remediation** (optional): Lambda adds default tags or stops resource

**Example Config Rule**:

```hcl
resource "aws_config_config_rule" "required_tags" {
  name = "required-tags"

  source {
    owner             = "AWS"
    source_identifier = "REQUIRED_TAGS"
  }

  input_parameters = jsonencode({
    tag1Key   = "Environment"
    tag2Key   = "Owner"
    tag3Key   = "CostCenter"
    tag4Key   = "ManagedBy"
    tag5Key   = "DataClassification"
  })
}

# Remediation: Add default tags
resource "aws_config_remediation_configuration" "add_default_tags" {
  config_rule_name = aws_config_config_rule.required_tags.name
  target_type      = "SSM_DOCUMENT"
  target_identifier = "AWS-PublishSNSNotification"

  parameter {
    name         = "AutomationAssumeRole"
    static_value = aws_iam_role.config_remediation.arn
  }

  parameter {
    name         = "Message"
    static_value = "Resource missing mandatory tags. Please add tags within 7 days or resource will be stopped."
  }
}
```

---

## Tag Reporting

### Cost Allocation Report

**Generated Monthly**: First business day of each month

**Sections**:
1. **Total Costs by Environment**: Prod vs Dev vs Staging
2. **Top 10 Expensive Resources**: Sorted by cost, with tags
3. **Untagged Resources**: Count and estimated cost
4. **Cost Center Breakdown**: Chargeback report
5. **Anomalies**: Resources with unusual tag combinations

**Example Report**:

```markdown
# Cloud Cost Report - October 2025

## Summary
- **Total Spend**: $4,250
- **Budget**: $5,000
- **Variance**: -15% (under budget)
- **Untagged Resources**: 3 (estimated $50/mo)

## By Environment
| Environment | Cost | % of Total |
|-------------|------|------------|
| prod        | $2,800 | 66% |
| staging     | $900   | 21% |
| dev         | $500   | 12% |
| sandbox     | $50    | 1% |

## By Cost Center
| CostCenter | Direct | Shared | Total | Budget | Variance |
|------------|--------|--------|-------|--------|----------|
| ENG-001    | $1,800 | $300   | $2,100 | $2,500 | -16% |
| SEC-001    | $1,200 | $200   | $1,400 | $1,500 | -7% |
| DATA-001   | $600   | $150   | $750   | $1,000 | -25% |

## Action Items
- [ ] Tag 3 untagged EBS volumes (vol-abc123, vol-def456, vol-ghi789)
- [ ] Review DATA-001 underutilization (significantly under budget)
- [ ] Investigate ENG-001 spike in compute costs (+20% MoM)
```

---

## Terraform Module: Auto-Tagging

```hcl
# modules/tagging/main.tf
variable "environment" {
  type = string
}

variable "owner" {
  type = string
}

variable "cost_center" {
  type = string
}

variable "data_classification" {
  type    = string
  default = "internal"
}

variable "project" {
  type    = string
  default = "cloud-netsec-blueprints"
}

variable "additional_tags" {
  type    = map(string)
  default = {}
}

locals {
  standard_tags = {
    Environment        = var.environment
    Owner              = var.owner
    CostCenter         = var.cost_center
    DataClassification = var.data_classification
    ManagedBy          = "Terraform"
    Project            = var.project
    TerraformWorkspace = terraform.workspace
    CreatedDate        = timestamp()
  }

  all_tags = merge(local.standard_tags, var.additional_tags)
}

output "tags" {
  value = local.all_tags
}
```

**Usage**:

```hcl
module "tags" {
  source = "./modules/tagging"

  environment         = "prod"
  owner               = "platform-team@company.com"
  cost_center         = "ENG-001"
  data_classification = "confidential"

  additional_tags = {
    Compliance = "SOC2"
  }
}

resource "aws_instance" "app" {
  ami           = data.aws_ami.ubuntu.id
  instance_type = "t3.medium"

  tags = merge(
    module.tags.tags,
    {
      Name = "app-server-prod-1a"
      Role = "application"
    }
  )
}
```

---

## Azure-Specific Tagging

### Inherit Tags from Resource Group

```hcl
# Azure Policy: Inherit tags from resource group
resource "azurerm_policy_definition" "inherit_rg_tags" {
  name         = "inherit-resource-group-tags"
  policy_type  = "Custom"
  mode         = "Indexed"
  display_name = "Inherit tags from resource group"

  policy_rule = jsonencode({
    if = {
      allOf = [
        {
          field  = "type"
          equals = "Microsoft.Compute/virtualMachines"
        },
        {
          field   = "tags['Environment']"
          exists  = "false"
        }
      ]
    }
    then = {
      effect = "modify"
      details = {
        roleDefinitionIds = [
          "/providers/Microsoft.Authorization/roleDefinitions/b24988ac-6180-42a0-ab88-20f7382dd24c"
        ]
        operations = [
          {
            operation = "addOrReplace"
            field     = "tags['Environment']"
            value     = "[resourceGroup().tags['Environment']]"
          }
        ]
      }
    }
  })
}

# Apply policy
resource "azurerm_resource_group_policy_assignment" "inherit_tags" {
  name                 = "inherit-tags"
  resource_group_id    = azurerm_resource_group.main.id
  policy_definition_id = azurerm_policy_definition.inherit_rg_tags.id
}
```

---

## References

- [AWS Tagging Best Practices](https://docs.aws.amazon.com/general/latest/gr/aws_tagging.html)
- [Azure Tagging Strategy](https://docs.microsoft.com/en-us/azure/cloud-adoption-framework/ready/azure-best-practices/resource-tagging)
- [AWS Cost Allocation Tags](https://docs.aws.amazon.com/awsaccountbilling/latest/aboutv2/cost-alloc-tags.html)
- [Terraform Tag Modules](https://registry.terraform.io/modules/terraform-aws-modules/tags/aws/latest)
- [Controls Matrix](./controls-matrix.md)
- [Security Baseline](../policy/)
