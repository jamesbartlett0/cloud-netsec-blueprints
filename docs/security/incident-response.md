# Incident Response Workflow

## Overview

This document defines the incident response (IR) process for security events in the multi-cloud network landing zones. The workflow follows the NIST Cybersecurity Framework: **Detect → Contain → Remediate → Report**.

**Scope**: Network perimeter, cross-cloud VPN, identity compromise, data exfiltration

**IR Team**: On-call rotation, escalation paths, external partners (AWS/Azure support, forensics firm)

---

## Incident Response Phases

```
┌────────────┐    ┌────────────┐    ┌────────────┐    ┌────────────┐
│  DETECT    │───>│  CONTAIN   │───>│ REMEDIATE  │───>│   REPORT   │
│            │    │            │    │            │    │            │
│ GuardDuty  │    │ Isolate    │    │ Patch      │    │ Post-      │
│ CloudTrail │    │ Block IP   │    │ Rotate     │    │ mortem     │
│ Alerts     │    │ Revoke IAM │    │ Update SGs │    │ Metrics    │
└────────────┘    └────────────┘    └────────────┘    └────────────┘
       │                 │                  │                 │
       └─────────────────┴──────────────────┴─────────────────┘
                   Continuous Improvement Loop
```

---

## Phase 1: Detect

### Detection Sources

| Source | Event Type | Severity | Response Time |
|--------|-----------|----------|---------------|
| GuardDuty | Cryptocurrency mining | Critical | Immediate (<5 min) |
| GuardDuty | SSH brute force | High | <15 min |
| CloudWatch | Root account usage | Critical | Immediate |
| CloudWatch | Security group changes | Medium | <1 hour |
| VPC Flow Logs | Unusual data transfer | High | <30 min |
| Azure Defender | Malware detected | Critical | Immediate |
| CloudTrail | IAM policy changes | Medium | <1 hour |

### Alert Channels

**Critical Alerts** (requires immediate action):
- PagerDuty → On-call engineer (phone call + SMS)
- Slack `#security-critical` (mention @security-team)
- Email to security@company.com

**High Alerts** (requires action within 15 min):
- Slack `#security-alerts`
- Email to security@company.com

**Medium Alerts** (review within 1 hour):
- Slack `#security-audit`
- Daily digest email

### Detection Playbooks

#### Detect-001: GuardDuty Finding

**Trigger**: GuardDuty finding with severity ≥ 7 (High or Critical)

**Automated Actions**:
1. Lambda triggered by EventBridge rule
2. Parse finding details (instance ID, IAM user, source IP)
3. Create incident ticket in Jira
4. Post to Slack `#security-alerts`
5. Query CloudTrail for related API calls (last 24h)
6. Snapshot EBS volumes for forensics

**Manual Review**:
- Review finding details in GuardDuty console
- Check for false positive (e.g., penetration testing)
- If legitimate threat, escalate to Containment phase

**Example Findings**:
- `CryptoCurrency:EC2/BitcoinTool.B!DNS`
- `Backdoor:EC2/C&CActivity.B!DNS`
- `UnauthorizedAccess:EC2/SSHBruteForce`

---

#### Detect-002: VPN Tunnel Down

**Trigger**: CloudWatch alarm `VPN-Tunnel-State-DOWN`

**Automated Actions**:
1. SNS notification → PagerDuty
2. Check both tunnels (primary + secondary)
3. Run network diagnostic (ping Azure VPN gateway)
4. Capture VPN connection logs

**Manual Review**:
- Verify if maintenance window
- Check AWS Health Dashboard for VPN service events
- Review VPN configuration changes (CloudTrail)
- Test failover to secondary tunnel

**Escalation**: If both tunnels down >15 min, page AWS Enterprise Support

---

#### Detect-003: Failed Console Login (MFA)

**Trigger**: CloudWatch metric filter `ConsoleLoginFailedMFA`

**Automated Actions**:
1. Increment metric counter
2. If ≥3 failures in 5 min → trigger alarm
3. Identify username from CloudTrail event
4. Send Slack notification with username + source IP

**Manual Review**:
- Check if legitimate user (contact via Slack/phone)
- If not user-initiated, assume credential compromise
- Escalate to Containment: Force password reset + revoke sessions

---

#### Detect-004: Unusual S3 Access Pattern

**Trigger**: GuardDuty finding `Exfiltration:S3/ObjectRead.Unusual`

**Automated Actions**:
1. Identify IAM role/user accessing S3
2. Query CloudTrail for S3 GetObject calls (last 1h)
3. Calculate data transfer volume
4. Snapshot S3 bucket access logs

**Manual Review**:
- Validate if legitimate (e.g., new data pipeline)
- Check S3 bucket `DataClassification` tag
- If `confidential` or `restricted` → escalate immediately
- Review IAM role assumption chain (who assumed the role?)

---

## Phase 2: Contain

**Objective**: Stop the attack from spreading, preserve evidence

### Containment Strategies

| Threat Type | Containment Action | Time to Execute |
|-------------|-------------------|-----------------|
| Compromised EC2 | Isolate instance (remove SG), snapshot EBS | <5 min |
| Compromised IAM | Revoke all sessions, attach DenyAll policy | <2 min |
| DDoS attack | Enable WAF rate limiting, contact AWS Shield | <10 min |
| VPN tunnel breach | Rotate PSK, disable VPN connection | <5 min |
| Malware on instance | Quarantine instance, stop outbound traffic | <5 min |

### Containment Playbooks

#### Contain-001: Isolate Compromised EC2 Instance

**When**: GuardDuty detects cryptocurrency mining or C&C communication

**Steps**:
1. **Preserve Evidence** (Do NOT terminate instance yet)
   ```bash
   # Create EBS snapshot
   aws ec2 create-snapshot \
     --volume-id vol-abc123 \
     --description "Forensics: GuardDuty finding GD-abc123"

   # Tag snapshot
   aws ec2 create-tags \
     --resources snap-xyz789 \
     --tags Key=Forensics,Value=GuardDuty-Finding Key=Date,Value=2025-10-02
   ```

2. **Isolate Instance** (prevent lateral movement)
   ```bash
   # Create isolation security group (deny all)
   aws ec2 create-security-group \
     --group-name sg-isolation-quarantine \
     --description "Quarantine for compromised instances" \
     --vpc-id vpc-abc123

   # No ingress rules, only egress to internal forensics server
   aws ec2 authorize-security-group-egress \
     --group-id sg-isolation \
     --protocol tcp \
     --port 22 \
     --cidr 10.3.20.0/24  # Security spoke forensics subnet

   # Apply to compromised instance
   aws ec2 modify-instance-attribute \
     --instance-id i-compromised \
     --groups sg-isolation
   ```

3. **Notify Team**
   ```bash
   # Post to Slack
   curl -X POST -H 'Content-type: application/json' \
     --data '{"text":"🚨 EC2 instance i-compromised isolated. Forensics in progress."}' \
     $SLACK_WEBHOOK_URL
   ```

4. **Capture Memory Dump** (for forensics)
   - Create AMI of running instance
   - Or use SSM Run Command to execute memory capture script

5. **Document Actions**
   - Update Jira ticket with containment steps
   - Screenshot GuardDuty finding
   - Record CloudTrail API calls

**Do NOT**:
- ❌ Terminate instance (lose volatile memory evidence)
- ❌ Reboot instance (lose running process info)
- ❌ Login to instance (contaminate evidence)

---

#### Contain-002: Revoke Compromised IAM Credentials

**When**: IAM access key leaked, unusual API calls detected

**Steps**:
1. **Immediately Disable Access Key**
   ```bash
   # Identify leaked key
   ACCESS_KEY_ID="AKIAIOSFODNN7EXAMPLE"

   # Disable (don't delete yet, for audit)
   aws iam update-access-key \
     --access-key-id $ACCESS_KEY_ID \
     --status Inactive \
     --user-name compromised-user
   ```

2. **Revoke All Active Sessions**
   ```bash
   # Attach deny-all policy
   aws iam put-user-policy \
     --user-name compromised-user \
     --policy-name DenyAllTemporary \
     --policy-document '{
       "Version": "2012-10-17",
       "Statement": [{
         "Effect": "Deny",
         "Action": "*",
         "Resource": "*"
       }]
     }'

   # Force session invalidation (revoke console sessions)
   aws iam update-user \
     --user-name compromised-user \
     --password-reset-required
   ```

3. **Audit Recent API Calls**
   ```bash
   # Query CloudTrail for actions by compromised key
   aws cloudtrail lookup-events \
     --lookup-attributes AttributeKey=AccessKeyId,AttributeValue=$ACCESS_KEY_ID \
     --start-time $(date -u -d '24 hours ago' +%s) \
     --max-results 100 \
     --output json > compromised-key-actions.json
   ```

4. **Identify Blast Radius**
   - Review actions taken (any new IAM users, S3 buckets, instances created?)
   - Check for privilege escalation attempts
   - Verify no backdoor IAM roles created

5. **Notify User**
   - Email user: "Your AWS credentials have been compromised and disabled"
   - Provide new temporary credentials
   - Require MFA setup before re-enabling

---

#### Contain-003: Block Malicious IP (NAT Gateway DoS)

**When**: GuardDuty detects SSH brute force from external IP

**Steps**:
1. **Block at Network ACL** (faster than Security Group)
   ```bash
   SOURCE_IP="203.0.113.50"

   # Add NACL deny rule (low rule number = high priority)
   aws ec2 create-network-acl-entry \
     --network-acl-id acl-abc123 \
     --rule-number 10 \
     --protocol -1 \
     --rule-action deny \
     --cidr-block $SOURCE_IP/32 \
     --ingress
   ```

2. **Block at WAF** (if ALB is target)
   ```bash
   # Create IP set
   aws wafv2 create-ip-set \
     --name blocked-ips \
     --scope REGIONAL \
     --ip-address-version IPV4 \
     --addresses $SOURCE_IP/32

   # Add WAF rule to block IP set
   # (requires existing WebACL)
   ```

3. **Document Block**
   - Add to incident ticket: IP, reason, block timestamp
   - Set expiration (remove block after 30 days if no further activity)

4. **Monitor for Evasion**
   - Check for new IPs from same ASN
   - Review VPC Flow Logs for related patterns

---

#### Contain-004: Emergency VPN Shutdown

**When**: Evidence of VPN tunnel compromise (unexpected traffic, PSK exposure)

**Steps**:
1. **Disable VPN Connection** (stop cross-cloud traffic)
   ```bash
   # Disable both tunnels
   aws ec2 modify-vpn-connection \
     --vpn-connection-id vpn-abc123 \
     --vpn-tunnel-options Tunnel1Disabled=true,Tunnel2Disabled=true
   ```

2. **Notify Stakeholders**
   - Slack: "🚨 VPN to Azure disabled due to security incident. Cross-cloud apps offline."
   - Email: Azure admins, application teams

3. **Rotate Pre-Shared Key**
   ```bash
   # Generate new PSK
   NEW_PSK=$(openssl rand -base64 32)

   # Store in Secrets Manager
   aws secretsmanager update-secret \
     --secret-id vpn/azure/preshared-key \
     --secret-string $NEW_PSK

   # Update VPN connection (requires re-creating VPN)
   # See Remediate phase for full VPN rebuild
   ```

4. **Audit Cross-Cloud Traffic**
   - Review VPC Flow Logs for Azure-bound traffic (10.100.0.0/12)
   - Check for data exfiltration patterns
   - Identify which applications were using VPN

---

## Phase 3: Remediate

**Objective**: Fix the root cause, restore normal operations

### Remediation Strategies

| Threat Type | Remediation Action | Validation |
|-------------|-------------------|------------|
| Compromised instance | Terminate instance, rebuild from clean AMI | Scan new instance with GuardDuty |
| Leaked credentials | Rotate all secrets, enforce MFA | No unauthorized API calls |
| Misconfigured SG | Update SG via Terraform, apply | Config Rule shows compliant |
| Unpatched vulnerability | SSM Patch Manager run, verify | Instance shows compliant patch level |
| VPN tunnel breach | Rebuild VPN with new PSK, update BGP | Tunnel up, no alerts for 24h |

### Remediation Playbooks

#### Remediate-001: Rebuild Compromised EC2 Instance

**When**: Containment complete, instance isolated

**Steps**:
1. **Terminate Compromised Instance**
   ```bash
   # After forensics complete (snapshot taken, memory dump captured)
   aws ec2 terminate-instances --instance-ids i-compromised
   ```

2. **Launch Clean Instance from Trusted AMI**
   ```bash
   # Use known-good AMI (pre-incident)
   aws ec2 run-instances \
     --image-id ami-clean-baseline \
     --instance-type t3.medium \
     --security-group-ids sg-app-tier \
     --subnet-id subnet-app-1a \
     --iam-instance-profile Name=app-role \
     --tag-specifications 'ResourceType=instance,Tags=[{Key=Name,Value=app-rebuilt}]' \
     --user-data file://bootstrap.sh
   ```

3. **Apply Configuration via Terraform**
   ```bash
   # Ensure instance is Terraform-managed (not manual)
   cd terraform/modules/ec2-app
   terraform apply -target=aws_instance.app_server
   ```

4. **Run Security Baseline**
   ```bash
   # SSM: Apply CIS hardening
   aws ssm send-command \
     --document-name "AWS-RunPatchBaseline" \
     --targets "Key=instanceids,Values=i-rebuilt" \
     --parameters "Operation=Install"

   # Install Falco (runtime security)
   aws ssm send-command \
     --document-name "AWS-RunShellScript" \
     --targets "Key=instanceids,Values=i-rebuilt" \
     --parameters 'commands=["curl -s https://falco.org/install | bash"]'
   ```

5. **Validation Checklist**
   - [ ] GuardDuty: No findings for rebuilt instance (24h)
   - [ ] Vulnerability scan: No critical/high CVEs
   - [ ] Application health check: Returns 200 OK
   - [ ] CloudWatch Logs: No error patterns
   - [ ] Instance profile: Least privilege IAM role

---

#### Remediate-002: Rotate All Secrets After Compromise

**When**: IAM credentials or secrets potentially exposed

**Secrets to Rotate**:
- Database passwords (RDS, Aurora)
- API keys (third-party services)
- VPN pre-shared keys
- TLS certificates (if private key exposed)
- SSH keys (EC2 key pairs)

**Steps**:
1. **Rotate RDS Password**
   ```bash
   # Generate new password
   NEW_DB_PASSWORD=$(openssl rand -base64 24)

   # Update in Secrets Manager
   aws secretsmanager update-secret \
     --secret-id rds/prod/master-password \
     --secret-string $NEW_DB_PASSWORD

   # Update RDS master password
   aws rds modify-db-instance \
     --db-instance-identifier prod-db \
     --master-user-password $NEW_DB_PASSWORD \
     --apply-immediately

   # Restart application to pick up new password
   aws ecs update-service \
     --cluster prod-cluster \
     --service app-service \
     --force-new-deployment
   ```

2. **Rotate API Keys**
   ```bash
   # Example: GitHub Personal Access Token
   # 1. Generate new token in GitHub Settings
   # 2. Update in Secrets Manager
   aws secretsmanager update-secret \
     --secret-id github/pat \
     --secret-string $NEW_GITHUB_TOKEN

   # 3. Update in GitHub Actions secrets (manual via UI)
   ```

3. **Rotate VPN PSK**
   ```bash
   # Generate new PSK
   NEW_PSK=$(openssl rand -base64 32)

   # Update Secrets Manager
   aws secretsmanager update-secret \
     --secret-id vpn/azure/preshared-key \
     --secret-string $NEW_PSK

   # Rebuild VPN connection (requires VPN downtime)
   # 1. Delete existing VPN connection
   # 2. Create new VPN connection with new PSK
   # 3. Update Azure Local Network Gateway
   # 4. Test connectivity
   ```

4. **Force Re-Authentication**
   ```bash
   # Invalidate all sessions for affected users
   aws iam delete-login-profile --user-name compromised-user
   aws iam create-login-profile \
     --user-name compromised-user \
     --password $(openssl rand -base64 16) \
     --password-reset-required
   ```

5. **Validation**
   - [ ] All applications using new secrets (check logs)
   - [ ] No authentication errors in CloudWatch
   - [ ] Old secrets deactivated (not deleted, for audit)
   - [ ] Secrets Manager: Rotation schedule updated

---

#### Remediate-003: Patch Security Group Misconfiguration

**When**: Config Rule detects SG allowing 0.0.0.0/0 on SSH/RDP

**Steps**:
1. **Identify Non-Compliant SG**
   ```bash
   # Query Config for non-compliant SGs
   aws configservice describe-compliance-by-config-rule \
     --config-rule-names restricted-ssh \
     --compliance-types NON_COMPLIANT \
     --output json
   ```

2. **Review SG Rules**
   ```bash
   # Get SG details
   aws ec2 describe-security-groups \
     --group-ids sg-abc123 \
     --query 'SecurityGroups[0].IpPermissions'
   ```

3. **Remove Overly Permissive Rule**
   ```bash
   # Remove 0.0.0.0/0 on SSH
   aws ec2 revoke-security-group-ingress \
     --group-id sg-abc123 \
     --protocol tcp \
     --port 22 \
     --cidr 0.0.0.0/0
   ```

4. **Add Correct Rule (VPN IP only)**
   ```bash
   # Allow SSH from VPN gateway only
   VPN_PUBLIC_IP="203.0.113.100"

   aws ec2 authorize-security-group-ingress \
     --group-id sg-abc123 \
     --protocol tcp \
     --port 22 \
     --cidr $VPN_PUBLIC_IP/32
   ```

5. **Update Terraform** (prevent drift)
   ```hcl
   # Fix in Terraform code
   resource "aws_security_group_rule" "ssh" {
     security_group_id = aws_security_group.bastion.id
     type              = "ingress"
     from_port         = 22
     to_port           = 22
     protocol          = "tcp"
     cidr_blocks       = [var.vpn_public_ip]  # Not 0.0.0.0/0
   }
   ```

6. **Apply Terraform**
   ```bash
   terraform plan  # Verify no changes (already fixed manually)
   terraform apply
   ```

7. **Validation**
   - [ ] Config Rule: Shows compliant
   - [ ] No 0.0.0.0/0 rules on ports 22, 3389, 3306, 5432
   - [ ] Terraform state matches actual SG configuration

---

## Phase 4: Report

**Objective**: Document incident, communicate to stakeholders, improve defenses

### Post-Incident Review (PIR)

**Conducted Within**: 48 hours of incident resolution

**Participants**: Security team, affected service owners, SRE, management

**Agenda**:
1. Incident timeline (detection → containment → remediation)
2. Root cause analysis (5 Whys)
3. Impact assessment (affected resources, data, users)
4. Lessons learned
5. Action items (prevent recurrence)

### PIR Template

```markdown
# Post-Incident Review: [Incident Title]

**Date**: 2025-10-02
**Severity**: Critical / High / Medium / Low
**Duration**: Detection to resolution time
**Incident Owner**: [Name]

## Summary
Brief description of what happened (2-3 sentences).

## Timeline (UTC)
| Time | Event |
|------|-------|
| 10:15 | GuardDuty detects cryptocurrency mining on i-abc123 |
| 10:17 | On-call engineer paged via PagerDuty |
| 10:20 | Instance isolated (SG changed to quarantine) |
| 10:25 | EBS snapshot created for forensics |
| 10:45 | Root cause identified: Vulnerable Jenkins plugin |
| 11:00 | Instance terminated, new instance launched |
| 11:30 | Jenkins patched, security scan passed |
| 12:00 | Incident resolved, monitoring for 24h |

## Impact
- **Affected Resources**: 1 EC2 instance (i-abc123)
- **Data Loss**: None
- **Service Downtime**: 45 min (Jenkins CI/CD unavailable)
- **Cost**: ~$50 (forensics snapshots, extra instance hours)

## Root Cause
Jenkins version 2.300 had a publicly known RCE vulnerability (CVE-2023-XXXXX).
Instance was not patched due to manual patching process (not automated).

## What Went Well
- ✅ GuardDuty detected mining activity within 5 min
- ✅ On-call engineer responded in <2 min
- ✅ Containment was fast (isolated instance in 5 min)
- ✅ No lateral movement to other instances

## What Went Poorly
- ❌ Instance was not patched (missed SSM Patch Manager run)
- ❌ Jenkins admin credentials were weak (no MFA)
- ❌ Initial response playbook missing (engineer improvised)

## Lessons Learned
1. Patching must be automated, not manual
2. All admin interfaces need MFA enforcement
3. Incident playbooks need to be documented

## Action Items
| Action | Owner | Due Date | Priority |
|--------|-------|----------|----------|
| Enable SSM Patch Manager for all instances | Ops Team | 2025-10-05 | P0 |
| Enforce MFA for Jenkins admin console | Security | 2025-10-04 | P0 |
| Create "Cryptocurrency Mining" runbook | Security | 2025-10-10 | P1 |
| Conduct tabletop exercise for IR team | Security | 2025-10-15 | P2 |
| Review all internet-facing apps for CVEs | Security | 2025-10-20 | P1 |

## Supporting Evidence
- GuardDuty finding: [Link to finding]
- CloudTrail logs: s3://cloudtrail-logs/2025/10/02/
- Forensics snapshot: snap-xyz789
- Jira ticket: SEC-1234
```

---

### Incident Metrics (Monthly Report)

**KPIs**:
- Mean Time to Detect (MTTD): Time from event to alert
- Mean Time to Respond (MTTR): Time from alert to containment
- Mean Time to Resolve (MTTR): Time from containment to remediation
- False Positive Rate: % of alerts that are not real incidents

**Dashboard** (CloudWatch):
```
┌─────────────────────────────────────────────────┐
│ Incident Response Metrics - October 2025       │
├─────────────────────────────────────────────────┤
│ Total Incidents: 12                             │
│ Critical: 1, High: 3, Medium: 5, Low: 3         │
│                                                 │
│ MTTD: 8 minutes (target: <10 min) ✅            │
│ MTTR (respond): 15 minutes (target: <30 min) ✅ │
│ MTTR (resolve): 2.5 hours (target: <4 hours) ✅ │
│                                                 │
│ False Positive Rate: 25% (target: <30%) ✅      │
│                                                 │
│ Top Incident Types:                             │
│ 1. SSH Brute Force: 5 incidents                │
│ 2. Security Group Changes: 3 incidents          │
│ 3. Unusual S3 Access: 2 incidents               │
└─────────────────────────────────────────────────┘
```

---

## Auto-Remediation (Future Phase)

### Auto-Remediation Triggers

**Implemented in Phase 4** (EventBridge → Lambda)

| Finding Type | Auto-Action | Risk |
|--------------|-------------|------|
| `SSHBruteForce` | Block source IP via NACL | Low |
| `BitcoinTool` | Isolate instance (snapshot + quarantine) | Medium |
| `UnauthorizedAPICall` | Revoke IAM session | High |
| `SecurityGroupChanged` | Revert to Terraform state | Medium |
| `S3BucketPublic` | Remove public ACL | Low |

**Lambda Example**: Auto-block SSH brute force

```python
import boto3

ec2 = boto3.client('ec2')

def lambda_handler(event, context):
    # Parse GuardDuty finding
    finding_type = event['detail']['type']

    if 'SSHBruteForce' in finding_type:
        # Extract source IP
        source_ip = event['detail']['service']['action']['networkConnectionAction']['remoteIpDetails']['ipAddressV4']

        # Block IP via NACL
        response = ec2.create_network_acl_entry(
            NetworkAclId='acl-abc123',  # Hub VPC NACL
            RuleNumber=10,
            Protocol='-1',
            RuleAction='deny',
            Ingress=True,
            CidrBlock=f'{source_ip}/32'
        )

        print(f'Blocked {source_ip} via NACL')

        # Send Slack notification
        # ... (omitted for brevity)

    return {'statusCode': 200, 'body': 'Auto-remediation complete'}
```

---

## IR Team & Contacts

### On-Call Rotation

| Week | Primary | Secondary | Escalation |
|------|---------|-----------|------------|
| Oct 1-7 | Alice (Security) | Bob (SRE) | CISO |
| Oct 8-14 | Bob (SRE) | Charlie (Ops) | VP Eng |
| Oct 15-21 | Charlie (Ops) | Alice (Security) | CISO |

**PagerDuty**: `cloud-security-oncall`

### Escalation Paths

**Level 1**: On-call engineer (GuardDuty alerts, CloudWatch alarms)
**Level 2**: Security team lead (critical findings, data breach)
**Level 3**: CISO (executive notification, legal/PR involvement)
**External**: AWS Enterprise Support (VPN outages, DDoS), Forensics firm (data breach)

### External Contacts

| Contact | Phone | Email | Use Case |
|---------|-------|-------|----------|
| AWS Support | +1-800-XXX-XXXX | aws-support@company.com | VPN issues, DDoS mitigation |
| Azure Support | +1-800-XXX-XXXX | azure-support@company.com | Azure Firewall, VPN gateway |
| Forensics Firm | +1-XXX-XXX-XXXX | forensics@firm.com | Data breach, legal hold |
| Legal | +1-XXX-XXX-XXXX | legal@company.com | Breach notification laws |

---

## References

- [NIST Cybersecurity Framework 2.0](https://www.nist.gov/cyberframework)
- [AWS Incident Response Guide](https://docs.aws.amazon.com/whitepapers/latest/aws-security-incident-response-guide/welcome.html)
- [Azure Security Incident Response](https://docs.microsoft.com/en-us/azure/security/fundamentals/incident-response)
- [SANS Incident Handler's Handbook](https://www.sans.org/reading-room/whitepapers/incident/incident-handlers-handbook-33901)
- [Threat Model](./threat-model.md)
- [Controls Matrix](./controls-matrix.md)
