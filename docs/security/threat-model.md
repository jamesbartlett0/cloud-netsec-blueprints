# Threat Model - Multi-Cloud Network Landing Zones

## Executive Summary

This document applies STRIDE threat modeling methodology to identify, categorize, and mitigate security threats across AWS and Azure hub-spoke network architectures. The analysis covers network perimeter, cross-cloud connectivity, and shared services.

**Methodology**: STRIDE (Spoofing, Tampering, Repudiation, Information Disclosure, Denial of Service, Elevation of Privilege)

**Scope**: Network layer (L2-L4), perimeter security, VPN connectivity, and identity/access controls

## Threat Model Overview

### Assets Under Protection

| Asset | Criticality | Location | Threat Surface |
|-------|-------------|----------|----------------|
| Hub VPC/VNet | Critical | 10.0.0.0/16, 10.100.0.0/16 | NAT, VPN, TGW |
| Spoke Production VPCs | Critical | 10.1.0.0/16, 10.101.0.0/16 | App/Data tiers |
| VPN Tunnel | Critical | Cross-cloud | IPsec endpoints |
| NAT Gateways | High | Hub DMZ | Internet egress |
| Bastion Hosts | High | Hub Mgmt | Admin access |
| Secrets (PSK, keys) | Critical | Secrets Manager/Key Vault | API access |

### Trust Boundaries

```
┌──────────────────────────────────────────────────────────┐
│ UNTRUSTED: Internet (0.0.0.0/0)                          │
└────────────────────┬─────────────────────────────────────┘
                     │
         ┌───────────▼──────────────┐
         │ BOUNDARY 1: DMZ Zone     │
         │ - ALB/App Gateway        │
         │ - NAT Gateways           │
         └───────────┬──────────────┘
                     │
         ┌───────────▼──────────────┐
         │ BOUNDARY 2: App Zone     │
         │ - Web/App servers        │
         └───────────┬──────────────┘
                     │
         ┌───────────▼──────────────┐
         │ BOUNDARY 3: Data Zone    │
         │ - Databases (TRUSTED)    │
         └──────────────────────────┘

┌──────────────────────────────────────────────────────────┐
│ BOUNDARY 4: Cross-Cloud VPN (10.0/12 ↔ 10.100/12)       │
└──────────────────────────────────────────────────────────┘
```

## STRIDE Analysis

### 1. Spoofing Identity Threats

#### S1: IP Address Spoofing on VPN Tunnel

**Threat**: Attacker spoofs legitimate AWS/Azure IP to gain cross-cloud access

| Attribute | Detail |
|-----------|--------|
| **Attack Vector** | Compromise VPN endpoint, inject packets with spoofed source IP |
| **Impact** | Unauthorized access to cross-cloud resources (CRITICAL) |
| **Likelihood** | Low (requires PSK compromise + network position) |
| **CIS Control** | CIS AWS 3.1, Azure 6.1 (Network Access Control) |

**Mitigations**:
- ✅ IPsec with pre-shared key authentication
- ✅ BGP MD5 authentication on VPN sessions
- ✅ AWS Security Groups: Reference source SG, not CIDR
- ✅ Azure NSGs: Service tags instead of IP ranges
- ✅ VPN tunnel monitoring (CloudWatch/Azure Monitor)

**Residual Risk**: LOW

---

#### S2: Bastion Host Impersonation

**Threat**: Attacker uses stolen SSH key to impersonate legitimate admin

| Attribute | Detail |
|-----------|--------|
| **Attack Vector** | Phishing admin for SSH private key, brute force weak keys |
| **Impact** | Full admin access to all spokes (CRITICAL) |
| **Likelihood** | Medium (social engineering is common) |
| **CIS Control** | CIS AWS 1.12, Azure 1.20 (MFA for admins) |

**Mitigations**:
- ✅ Enforce MFA for bastion access (AWS SSM Session Manager)
- ✅ Short-lived SSH certificates (signed by CA, expire 1h)
- ✅ Azure Bastion (no public IPs, no SSH keys)
- ✅ CloudTrail/Activity logs for all bastion sessions
- ⚠️ TODO: Implement CIS benchmark SSH hardening

**Residual Risk**: MEDIUM → Implement SSH certificates

---

#### S3: Compromised IAM Credentials

**Threat**: AWS access key or Azure service principal credentials leaked

| Attribute | Detail |
|-----------|--------|
| **Attack Vector** | Credentials in Git, CI/CD logs, developer laptop |
| **Impact** | API access to create/delete resources (CRITICAL) |
| **Likelihood** | High (common misconfiguration) |
| **CIS Control** | CIS AWS 1.3, Azure 1.21 (Credential rotation) |

**Mitigations**:
- ✅ OIDC for GitHub Actions (no long-lived credentials)
- ✅ Secrets Manager/Key Vault for application credentials
- ✅ AWS IAM Access Analyzer (detect external exposure)
- ✅ Credential scanning in pre-commit hooks (truffleHog)
- ✅ 90-day credential rotation policy (automated)

**Residual Risk**: LOW

---

### 2. Tampering Threats

#### T1: Man-in-the-Middle on VPN Tunnel

**Threat**: Attacker intercepts/modifies VPN traffic between AWS and Azure

| Attribute | Detail |
|-----------|--------|
| **Attack Vector** | BGP hijacking, routing table poisoning |
| **Impact** | Data integrity compromise, traffic redirection (HIGH) |
| **Likelihood** | Very Low (requires ISP-level compromise) |
| **CIS Control** | CIS AWS 3.9 (Encryption in transit) |

**Mitigations**:
- ✅ IPsec with AES-256 encryption
- ✅ IKEv2 with DH Group 14 (2048-bit)
- ✅ Perfect Forward Secrecy (PFS) enabled
- ✅ VPN tunnel state monitoring (alerts on DOWN)
- ✅ RPKI/BGPsec validation (future enhancement)

**Residual Risk**: VERY LOW

---

#### T2: Configuration Drift (Infrastructure as Code)

**Threat**: Manual changes to Terraform-managed resources

| Attribute | Detail |
|-----------|--------|
| **Attack Vector** | Admin bypasses IaC, makes console changes |
| **Impact** | Inconsistent security posture, audit failures (MEDIUM) |
| **Likelihood** | Medium (convenience over process) |
| **CIS Control** | CIS AWS 3.1, Azure 2.3 (Change management) |

**Mitigations**:
- ✅ AWS Config Rules: Detect drift from Terraform state
- ✅ Azure Policy: Deny manual changes to tagged resources
- ✅ GitHub branch protection (require PR for main)
- ✅ Terraform Cloud drift detection (daily scans)
- ⚠️ TODO: SCPs to deny console changes in production

**Residual Risk**: MEDIUM → Implement SCPs

---

#### T3: Route Table Manipulation

**Threat**: Attacker modifies route tables to redirect traffic

| Attribute | Detail |
|-----------|--------|
| **Attack Vector** | Compromised IAM role with ec2:CreateRoute permissions |
| **Impact** | Traffic hijacking, data exfiltration (HIGH) |
| **Likelihood** | Low (requires IAM compromise) |
| **CIS Control** | CIS AWS 3.1 (Network ACLs) |

**Mitigations**:
- ✅ IAM policies: Least privilege (no ec2:* in production)
- ✅ VPC Flow Logs: Detect unexpected traffic patterns
- ✅ GuardDuty: Alert on route table changes
- ✅ Terraform state lock: Prevent concurrent modifications
- ✅ SCP: Deny route table modifications outside IaC role

**Residual Risk**: LOW

---

### 3. Repudiation Threats

#### R1: Deletion of Audit Logs

**Threat**: Attacker deletes CloudTrail/Activity logs to hide actions

| Attribute | Detail |
|-----------|--------|
| **Attack Vector** | Compromised admin deletes S3 CloudTrail bucket |
| **Impact** | No forensic evidence, compliance violation (HIGH) |
| **Likelihood** | Low (requires high-privilege access) |
| **CIS Control** | CIS AWS 3.1, Azure 5.1.1 (Audit logging) |

**Mitigations**:
- ✅ CloudTrail log file integrity validation (SHA-256 hashes)
- ✅ S3 Bucket Policy: Deny deletion, even by root
- ✅ S3 Object Lock (WORM): 7-year retention
- ✅ Cross-region replication to secondary region
- ✅ Azure Activity Logs → Log Analytics (immutable)
- ✅ SIEM integration (Sentinel, Splunk) for real-time export

**Residual Risk**: VERY LOW

---

#### R2: Unauthorized VPN Configuration Changes

**Threat**: Admin denies making VPN changes that caused outage

| Attribute | Detail |
|-----------|--------|
| **Attack Vector** | No accountability for VPN gateway modifications |
| **Impact** | Cannot attribute outage root cause (MEDIUM) |
| **Likelihood** | Medium (human error common) |
| **CIS Control** | CIS AWS 3.1, Azure 5.1.3 (Change logging) |

**Mitigations**:
- ✅ CloudTrail: Log all VPN API calls (who, when, what)
- ✅ Azure Activity Logs: Track VPN connection changes
- ✅ Terraform state: Git commits show change author
- ✅ Slack/Teams notifications on VPN config changes
- ✅ Require ticket number in Terraform commit messages

**Residual Risk**: LOW

---

### 4. Information Disclosure Threats

#### I1: Exposure of VPN Pre-Shared Key

**Threat**: VPN PSK stored in plaintext (Git, logs, Terraform state)

| Attribute | Detail |
|-----------|--------|
| **Attack Vector** | PSK leaked in Terraform state file, wiki documentation |
| **Impact** | VPN tunnel compromise, full cross-cloud access (CRITICAL) |
| **Likelihood** | Medium (common IaC mistake) |
| **CIS Control** | CIS AWS 2.1.3, Azure 8.1 (Secrets management) |

**Mitigations**:
- ✅ AWS Secrets Manager: Store PSK, reference ARN in Terraform
- ✅ Azure Key Vault: Store PSK with RBAC access control
- ✅ Terraform state encryption (S3 bucket + KMS)
- ✅ .gitignore: Exclude terraform.tfstate, .tfvars
- ✅ Pre-commit hook: Scan for secrets (truffleHog, git-secrets)
- ✅ Rotate PSK every 90 days (automated Lambda/Function)

**Residual Risk**: LOW

---

#### I2: VPC Flow Logs Containing Sensitive Data

**Threat**: Flow logs capture application-layer data (PII, tokens)

| Attribute | Detail |
|-----------|--------|
| **Attack Vector** | Developer queries Flow Logs, extracts API keys from payloads |
| **Impact** | PII exposure, compliance violation (MEDIUM) |
| **Likelihood** | Very Low (Flow Logs are L3/L4 only, no payloads) |
| **CIS Control** | CIS AWS 3.9 (Data protection) |

**Mitigations**:
- ✅ VPC Flow Logs: Capture headers only (5-tuple: src, dst, port, proto)
- ✅ S3 bucket encryption (SSE-KMS)
- ✅ Bucket policy: Restrict access to security team only
- ✅ TLS 1.3 for all application traffic (encrypt payloads)
- ⚠️ TODO: Data classification policy (mark sensitive subnets)

**Residual Risk**: VERY LOW

---

#### I3: Unencrypted Data at Rest (EBS, RDS)

**Threat**: Snapshot exported by attacker contains plaintext data

| Attribute | Detail |
|-----------|--------|
| **Attack Vector** | Compromised IAM role creates EBS snapshot, shares publicly |
| **Impact** | Database backup exfiltration (CRITICAL) |
| **Likelihood** | Low (requires snapshot + share permissions) |
| **CIS Control** | CIS AWS 2.1.1, Azure 3.7 (Encryption at rest) |

**Mitigations**:
- ✅ AWS: Enforce EBS encryption by default (account-level)
- ✅ RDS: Enable encryption at creation (cannot enable later)
- ✅ Azure: Disk encryption enabled by default (SSE)
- ✅ SCP: Deny creation of unencrypted volumes
- ✅ Config Rule: Auto-remediate unencrypted resources
- ✅ KMS keys: Customer-managed (CMK) for audit trail

**Residual Risk**: VERY LOW

---

### 5. Denial of Service Threats

#### D1: NAT Gateway Exhaustion

**Threat**: Malicious traffic saturates NAT gateway port allocation

| Attribute | Detail |
|-----------|--------|
| **Attack Vector** | Botnet floods app tier with connections |
| **Impact** | Legitimate egress traffic blocked (HIGH) |
| **Likelihood** | Medium (DDoS common for public services) |
| **CIS Control** | CIS AWS 3.7 (DDoS protection) |

**Mitigations**:
- ✅ AWS Shield Standard (free DDoS protection)
- ✅ NAT Gateway auto-scaling (AWS managed)
- ✅ CloudWatch Alarms: Port allocation errors
- ✅ Rate limiting at ALB (WAF rules)
- ⚠️ Consider: Shield Advanced ($3k/mo) for production
- ✅ Multiple NAT Gateways (one per AZ) for redundancy

**Residual Risk**: MEDIUM → Evaluate Shield Advanced

---

#### D2: VPN Tunnel Bandwidth Saturation

**Threat**: Cross-cloud traffic exceeds VPN capacity (1.25 Gbps)

| Attribute | Detail |
|-----------|--------|
| **Attack Vector** | Misconfigured app sends excessive data to Azure |
| **Impact** | VPN tunnel congestion, packet loss (MEDIUM) |
| **Likelihood** | Medium (application bugs common) |
| **CIS Control** | CIS AWS 3.3 (Network monitoring) |

**Mitigations**:
- ✅ CloudWatch: Alert on tunnel bandwidth > 80%
- ✅ VPC Flow Logs: Identify top talkers
- ✅ GuardDuty: Detect unusual data transfer volumes
- ✅ QoS policies: Prioritize critical traffic
- ⚠️ TODO: Upgrade to Direct Connect/ExpressRoute for >1 Gbps
- ✅ Application quotas: Limit API call rates

**Residual Risk**: MEDIUM → Monitor and upgrade if needed

---

#### D3: Resource Exhaustion via API Abuse

**Threat**: Attacker creates thousands of EC2 instances

| Attribute | Detail |
|-----------|--------|
| **Attack Vector** | Compromised IAM role with ec2:RunInstances |
| **Impact** | Account quota exhaustion, massive bill (HIGH) |
| **Likelihood** | Low (requires IAM compromise + no quotas) |
| **CIS Control** | CIS AWS 1.16 (Service limits) |

**Mitigations**:
- ✅ AWS Service Quotas: Set limits per region
- ✅ IAM Conditions: Limit instance types, counts
- ✅ Budget alerts: SNS notification at 80% of forecast
- ✅ GuardDuty: Detect cryptocurrency mining patterns
- ✅ SCP: Deny expensive instance types (p3, p4)
- ✅ Terraform: Use auto-scaling with max instance caps

**Residual Risk**: LOW

---

### 6. Elevation of Privilege Threats

#### E1: Container Escape to Host

**Threat**: Attacker escapes container, gains EC2 instance root

| Attribute | Detail |
|-----------|--------|
| **Attack Vector** | Kernel exploit (dirty pipe, etc.) |
| **Impact** | Instance compromise, lateral movement (HIGH) |
| **Likelihood** | Low (requires 0-day or unpatched kernel) |
| **CIS Control** | CIS AWS 5.1 (Patch management) |

**Mitigations**:
- ✅ SSM Patch Manager: Auto-patch EC2 weekly
- ✅ Bottlerocket OS (minimal attack surface)
- ✅ Security Groups: Prevent lateral movement
- ✅ GuardDuty Runtime Monitoring (EKS)
- ⚠️ TODO: Implement Falco for runtime detection
- ✅ IMDSv2 required (prevents SSRF to metadata)

**Residual Risk**: MEDIUM → Implement runtime detection

---

#### E2: IAM Role Assumption Chain

**Threat**: Attacker assumes increasingly privileged roles

| Attribute | Detail |
|-----------|--------|
| **Attack Vector** | Role A → Role B → Role Admin (chained assumptions) |
| **Impact** | Full account takeover (CRITICAL) |
| **Likelihood** | Low (requires trust policy misconfiguration) |
| **CIS Control** | CIS AWS 1.15, Azure 1.23 (Least privilege) |

**Mitigations**:
- ✅ IAM Access Analyzer: Detect external trust relationships
- ✅ SCPs: Require MFA for role assumption
- ✅ Condition: aws:MultiFactorAuthPresent = true
- ✅ IAM policies: Explicit Deny on sts:AssumeRole for sensitive roles
- ✅ CloudTrail: Alert on AssumeRole for admin roles
- ✅ Separate accounts for prod/dev (no cross-account admin)

**Residual Risk**: LOW

---

#### E3: Privilege Escalation via Security Group Modification

**Threat**: Attacker modifies SG to allow 0.0.0.0/0 on RDP/SSH

| Attribute | Detail |
|-----------|--------|
| **Attack Vector** | Compromised developer IAM role |
| **Impact** | Internet-facing database, data breach (CRITICAL) |
| **Likelihood** | Medium (developers often have ec2:AuthorizeSecurityGroupIngress) |
| **CIS Control** | CIS AWS 5.1, Azure 6.1 (Network segmentation) |

**Mitigations**:
- ✅ SCP: Deny 0.0.0.0/0 ingress on ports 22, 3389, 3306, 5432
- ✅ AWS Config: Auto-remediate overly permissive SGs
- ✅ IAM policies: Condition on source IP (only VPN range)
- ✅ GuardDuty: Alert on security group changes
- ✅ Terraform: All SGs managed via IaC (no console changes)

**Residual Risk**: LOW

---

## Threat Summary Table

| ID | Threat | Category | Severity | Likelihood | Risk | Mitigation Status |
|----|--------|----------|----------|------------|------|-------------------|
| S1 | VPN IP Spoofing | Spoofing | Critical | Low | Medium | ✅ Implemented |
| S2 | Bastion Impersonation | Spoofing | Critical | Medium | High | ⚠️ Partial |
| S3 | IAM Credential Leak | Spoofing | Critical | High | High | ✅ Implemented |
| T1 | VPN MITM | Tampering | High | Very Low | Low | ✅ Implemented |
| T2 | Config Drift | Tampering | Medium | Medium | Medium | ⚠️ Partial |
| T3 | Route Table Manipulation | Tampering | High | Low | Medium | ✅ Implemented |
| R1 | Audit Log Deletion | Repudiation | High | Low | Medium | ✅ Implemented |
| R2 | VPN Change Denial | Repudiation | Medium | Medium | Medium | ✅ Implemented |
| I1 | VPN PSK Exposure | Info Disclosure | Critical | Medium | High | ✅ Implemented |
| I2 | Flow Log Data Leak | Info Disclosure | Medium | Very Low | Low | ✅ Implemented |
| I3 | Unencrypted Data | Info Disclosure | Critical | Low | Medium | ✅ Implemented |
| D1 | NAT Exhaustion | DoS | High | Medium | High | ⚠️ Partial |
| D2 | VPN Saturation | DoS | Medium | Medium | Medium | ⚠️ Monitor |
| D3 | API Resource Abuse | DoS | High | Low | Medium | ✅ Implemented |
| E1 | Container Escape | Elevation | High | Low | Medium | ⚠️ Partial |
| E2 | IAM Role Chain | Elevation | Critical | Low | Medium | ✅ Implemented |
| E3 | Security Group Bypass | Elevation | Critical | Medium | High | ✅ Implemented |

**Risk Levels**: Critical (16), High (6), Medium (8), Low (3)
**Mitigation**: ✅ Implemented (11), ⚠️ Partial (5), ❌ Planned (1)

## Priority Remediation Plan

### High-Priority (Complete in Phase 1)

1. **S2 - Bastion SSH Certificates**
   - Implement short-lived SSH certificates (1-hour TTL)
   - AWS: SSM Session Manager (no SSH keys)
   - Azure: Azure Bastion (native solution)

2. **T2 - Config Drift Detection**
   - Deploy AWS Config Rules for Terraform-managed resources
   - Azure Policy: Audit/Deny manual changes
   - Service Control Policies to enforce IaC-only changes

3. **D1 - NAT Gateway Resilience**
   - Evaluate AWS Shield Advanced for production
   - Implement WAF rate limiting
   - Document runbook for NAT failover

### Medium-Priority (Complete in Phase 2)

4. **E1 - Container Runtime Security**
   - Deploy Falco for runtime anomaly detection
   - Implement Pod Security Standards (EKS)
   - Regular vulnerability scanning (Trivy, Snyk)

5. **D2 - VPN Capacity Planning**
   - Monitor tunnel utilization for 30 days
   - Upgrade to Direct Connect if >500 Mbps sustained
   - Implement application-level QoS

## Monitoring & Detection

### Key Metrics

| Metric | Tool | Threshold | Action |
|--------|------|-----------|--------|
| VPN Tunnel State | CloudWatch | DOWN > 1 min | PagerDuty alert |
| Failed SSH Attempts | CloudTrail | >10 in 5 min | Block source IP |
| Security Group Changes | GuardDuty | Any change | Slack notification |
| IAM AssumeRole (admin) | CloudWatch Logs | Any call | Require MFA verification |
| Unencrypted Volume | Config | Any creation | Auto-delete + alert |

### Detection Rules

**GuardDuty Findings**:
- `UnauthorizedAccess:EC2/SSHBruteForce`
- `Recon:EC2/PortProbeEMRUnprotectedPort`
- `CryptoCurrency:EC2/BitcoinTool.B!DNS`

**AWS Config Rules**:
- `vpc-flow-logs-enabled`
- `encrypted-volumes`
- `restricted-ssh` (no 0.0.0.0/0 on port 22)

## References

- [STRIDE Threat Modeling](https://docs.microsoft.com/en-us/azure/security/develop/threat-modeling-tool-threats)
- [OWASP Threat Modeling](https://owasp.org/www-community/Threat_Modeling)
- [CIS AWS Foundations Benchmark v1.5](https://www.cisecurity.org/benchmark/amazon_web_services)
- [CIS Azure Foundations Benchmark v2.0](https://www.cisecurity.org/benchmark/azure)
- [AWS Security Best Practices](https://aws.amazon.com/architecture/security-identity-compliance/)
