# Cloud Networking + Security Blueprints - Project Plan

**Project Code**: CLOUD-NETSEC-BP
**Duration**: 6 Weeks (42 Days)
**Target Completion**: Week of 2025-11-13
**Project Manager**: James
**Status**: Planning Phase

---

## Executive Summary

### Project Objective
Create a production-grade, public GitHub repository demonstrating multi-cloud network landing zones (AWS + Azure) with automated security orchestration, comprehensive monitoring, and serverless threat response. Position as technical portfolio centerpiece for roles paying AUD $140k-$180k in cloud/network architecture, platform engineering, and security automation.

### Success Criteria
1. **Technical Deliverables**: Fully functional AWS and Azure landing zones with hub-spoke topology, deployable via IaC with <5min provisioning time
2. **Automation Quality**: Event-driven security automation with <30s response time from threat detection to mitigation
3. **Documentation Excellence**: Complete runbooks, architecture diagrams, and 2 detailed case studies
4. **Industry Validation**: 500+ GitHub stars, 10+ LinkedIn posts, 3+ meaningful connections with hiring managers/architects
5. **Career Outcome**: 5+ qualified interview opportunities within 8 weeks of project completion

### Project Scope Boundaries

**IN SCOPE:**
- AWS and Azure hub-spoke network landing zones
- Terraform as primary IaC (90% of code)
- Bicep and CloudFormation reference implementations
- Event-driven security automation (GuardDuty/Defender → auto-block)
- Comprehensive monitoring with SLOs
- CI/CD pipeline with security scanning
- Production-ready documentation and runbooks
- LinkedIn content strategy and networking plan

**OUT OF SCOPE:**
- GCP implementation (future phase)
- Kubernetes/container networking (separate project)
- Application-layer security (WAF, OWASP)
- Compliance frameworks (SOC2, PCI-DSS) - reference only
- Multi-region DR/failover (simplified single-region per cloud)
- Production support or SLA commitments

---

## Work Breakdown Structure (WBS)

### Phase 1: Foundation & Design (Week 1)
**Duration**: 7 days
**Start**: 2025-10-02 | **End**: 2025-10-08

#### 1.1 Project Setup & Repository Scaffolding
**Owner**: James | **Priority**: P0 | **Effort**: 8h

**Tasks**:
- [x] Create GitHub repository with MIT license
- [ ] Initialize repo structure (modules/, examples/, automation/, policy/, diag/, docs/)
- [ ] Configure branch protection rules (main requires PR + CI pass)
- [ ] Setup GitHub Projects board with automated workflows
- [ ] Create CONTRIBUTING.md, CODE_OF_CONDUCT.md, SECURITY.md
- [ ] Initialize pre-commit hooks (terraform-fmt, tflint, markdown-lint)
- [ ] Setup GitHub Actions CI/CD skeleton (.github/workflows/)

**Deliverables**:
- Repository: `github.com/<username>/cloud-netsec-blueprints`
- File: `/README.md` (initial skeleton)
- File: `/CONTRIBUTING.md`
- File: `/docs/ARCHITECTURE.md` (template)
- Folder: All primary directories created

**Success Criteria**:
- [ ] Repository public and accessible
- [ ] All standard GitHub community files present
- [ ] Pre-commit hooks functioning locally
- [ ] CI pipeline runs on push (even if empty tests)

**Dependencies**: None (critical path start)

**Risks**:
- Risk: Scope creep during setup → **Mitigation**: Use checklist, timebox to 8h
- Risk: CI/CD complexity delays → **Mitigation**: Start with minimal pipeline, iterate

---

#### 1.2 Network Architecture Design
**Owner**: James | **Priority**: P0 | **Effort**: 12h

**Tasks**:
- [ ] Design CIDR allocation scheme (AWS: 10.0.0.0/16 hub, 10.1-3.0.0/16 spokes; Azure: 10.100.0.0/16 hub, 10.101-103.0.0/16 spokes)
- [ ] Document subnet segmentation (DMZ, app, data, mgmt zones)
- [ ] Design routing tables and default routes
- [ ] Plan NAT gateway/Azure NAT placement
- [ ] Design VPN/IPsec connectivity (hub-to-hub or separate)
- [ ] Document firewall rule taxonomy (categories, naming conventions)
- [ ] Create network topology Mermaid diagrams (AWS, Azure, hybrid)
- [ ] Document IPAM strategy and reservation process

**Deliverables**:
- File: `/docs/architecture/network-design.md`
- File: `/diag/aws-topology.mmd`
- File: `/diag/azure-topology.mmd`
- File: `/diag/hybrid-connectivity.mmd`
- File: `/docs/architecture/cidr-allocation.md`

**Success Criteria**:
- [ ] No CIDR overlaps between AWS/Azure
- [ ] Subnet sizing supports 100+ resources per spoke
- [ ] Diagrams render correctly on GitHub
- [ ] Peer review by 1 external architect (Reddit/Discord)

**Dependencies**: 1.1 (repo structure)

**Risks**:
- Risk: CIDR conflicts discovered late → **Mitigation**: Use IPAM spreadsheet, validate early
- Risk: Over-engineering topology → **Mitigation**: Start simple (3 spokes), document expansion

---

#### 1.3 Security & Compliance Framework
**Owner**: James | **Priority**: P0 | **Effort**: 10h

**Tasks**:
- [ ] Define threat model (STRIDE analysis for network perimeter)
- [ ] Document security controls mapping (CIS AWS/Azure benchmarks)
- [ ] Design encryption at rest/transit strategy
- [ ] Plan identity and access model (least privilege roles/policies)
- [ ] Define tagging/labeling taxonomy (cost allocation, compliance)
- [ ] Create security baseline checklist (SCPs, Azure Policies)
- [ ] Document secrets management approach (AWS Secrets Manager, Key Vault)
- [ ] Define incident response workflow (detect → contain → remediate → report)

**Deliverables**:
- File: `/docs/security/threat-model.md`
- File: `/docs/security/controls-matrix.md`
- File: `/docs/security/tagging-standards.md`
- File: `/docs/security/incident-response.md`
- File: `/policy/aws-scps/baseline.json` (skeleton)
- File: `/policy/azure-policy/baseline.json` (skeleton)

**Success Criteria**:
- [ ] Threat model covers 10+ threat scenarios
- [ ] Security controls map to CIS benchmarks
- [ ] Tagging strategy supports cost allocation + compliance
- [ ] IR workflow includes auto-remediation triggers

**Dependencies**: 1.2 (architecture decisions inform security)

**Risks**:
- Risk: Analysis paralysis on threat modeling → **Mitigation**: Timebox to 4h, iterate later
- Risk: Overly restrictive policies break functionality → **Mitigation**: Test policies in dev spoke first

---

#### 1.4 Tooling & Development Environment
**Owner**: James | **Priority**: P1 | **Effort**: 6h

**Tasks**:
- [ ] Setup Terraform version management (tfenv or asdf)
- [ ] Configure AWS CLI profiles (dev, test, prod)
- [ ] Configure Azure CLI profiles
- [ ] Install and configure tflint, tfsec, checkov
- [ ] Setup VSCode/IDE extensions (Terraform, YAML, Mermaid)
- [ ] Create Makefile with common tasks (init, plan, apply, test, clean)
- [ ] Document local development prerequisites
- [ ] Create docker-compose for local testing (optional)

**Deliverables**:
- File: `/Makefile`
- File: `/docs/DEVELOPMENT.md`
- File: `/.tool-versions` (asdf) or `/.terraform-version`
- File: `/scripts/setup-env.sh` (bootstrap script)

**Success Criteria**:
- [ ] `make init` successfully initializes both AWS and Azure workspaces
- [ ] `make validate` runs tflint + tfsec without errors
- [ ] All tools documented with version pins
- [ ] Setup script tested on clean Ubuntu/macOS environment

**Dependencies**: 1.1 (repo exists)

**Risks**:
- Risk: Version conflicts between tools → **Mitigation**: Use Docker for tool isolation
- Risk: Cloud credential complexity → **Mitigation**: Document credential precedence clearly

---

#### 1.5 Industry Presence - Week 1 Activities
**Owner**: James | **Priority**: P1 | **Effort**: 4h

**Tasks**:
- [ ] Update LinkedIn headline: "Cloud Network Architect | AWS/Azure Landing Zones | Infrastructure Automation"
- [ ] Draft LinkedIn post #1: "Announcing Cloud Network Blueprints project - goals and why"
- [ ] Identify 20 target companies (LinkedIn job search filters)
- [ ] Join 3 relevant communities (AWS/Azure Slack, Reddit r/devops, r/networking)
- [ ] Connect with 5 cloud architects (personalized messages)
- [ ] Schedule content calendar (6 posts over 6 weeks)

**Deliverables**:
- File: `/docs/career/linkedin-content-plan.md`
- File: `/docs/career/target-companies.md`
- LinkedIn Post #1 (published)

**Success Criteria**:
- [ ] Post reaches 100+ impressions
- [ ] 2+ new connections accept
- [ ] 1+ comment/engagement on post

**Dependencies**: 1.1 (repo public for linking)

---

### Phase 2: AWS Landing Zone Implementation (Week 2)
**Duration**: 7 days
**Start**: 2025-10-09 | **End**: 2025-10-15

#### 2.1 AWS Hub VPC & Core Networking
**Owner**: James | **Priority**: P0 | **Effort**: 16h

**Tasks**:
- [ ] Create Terraform module: `modules/aws/vpc-hub`
- [ ] Implement VPC with 6 subnets (public, private-app, private-data across 2 AZs)
- [ ] Deploy Internet Gateway
- [ ] Deploy NAT Gateways (2x, HA across AZs)
- [ ] Configure route tables (public, private per AZ)
- [ ] Implement VPC Flow Logs → CloudWatch Logs
- [ ] Deploy AWS Transit Gateway (hub for spoke attachment)
- [ ] Configure default route (0.0.0.0/0 → NAT)
- [ ] Implement DHCP options set (custom DNS if needed)
- [ ] Add outputs (VPC ID, subnet IDs, TGW ID, etc.)
- [ ] Write module README with usage examples

**Deliverables**:
- Module: `/modules/aws/vpc-hub/` (main.tf, variables.tf, outputs.tf, README.md)
- Example: `/examples/aws/hub-minimal/` (working deployment)
- Tests: `/modules/aws/vpc-hub/tests/` (terraform validate + tflint)

**Success Criteria**:
- [ ] `terraform apply` completes in <5min
- [ ] Flow logs appear in CloudWatch within 2min
- [ ] NAT Gateway tested (EC2 in private subnet can reach internet)
- [ ] tfsec/checkov pass with 0 high/critical findings
- [ ] Module documentation includes cost estimate ($50-100/month)

**Dependencies**: 1.2 (CIDR design), 1.4 (tooling setup)

**Risks**:
- Risk: NAT Gateway costs escalate → **Mitigation**: Use single NAT for dev, document HA pattern
- Risk: Transit Gateway complexity → **Mitigation**: Start with simple attachment, defer advanced routing

---

#### 2.2 AWS Spoke VPCs & Connectivity
**Owner**: James | **Priority**: P0 | **Effort**: 12h

**Tasks**:
- [ ] Create Terraform module: `modules/aws/vpc-spoke`
- [ ] Implement parameterized spoke VPC (single AZ for cost, multi-AZ optional)
- [ ] Configure Transit Gateway attachment
- [ ] Update route tables (spoke → TGW for inter-VPC traffic)
- [ ] Implement VPC Flow Logs per spoke
- [ ] Deploy 3 spoke examples (dev, test, prod environments)
- [ ] Test connectivity (ping between spokes via TGW)
- [ ] Document spoke provisioning runbook

**Deliverables**:
- Module: `/modules/aws/vpc-spoke/`
- Examples: `/examples/aws/spoke-dev/`, `/examples/aws/spoke-test/`, `/examples/aws/spoke-prod/`
- File: `/docs/runbooks/aws-provision-spoke.md`

**Success Criteria**:
- [ ] Spoke VPC deploys in <3min
- [ ] EC2 in dev spoke can ping EC2 in test spoke (via TGW)
- [ ] Flow logs confirm inter-spoke traffic
- [ ] Spoke module reusable (tested with 3 different CIDR blocks)

**Dependencies**: 2.1 (hub VPC + TGW exist)

**Risks**:
- Risk: TGW route table complexity → **Mitigation**: Document route propagation clearly
- Risk: CIDR typos cause connectivity issues → **Mitigation**: Use variables validation

---

#### 2.3 AWS Security Controls (SG, NACL, Network Firewall)
**Owner**: James | **Priority**: P0 | **Effort**: 14h

**Tasks**:
- [ ] Create security group modules (bastion, app-tier, data-tier)
- [ ] Implement NACL baseline (deny all inbound by default, explicit allows)
- [ ] Deploy AWS Network Firewall in hub VPC
- [ ] Configure stateful firewall rules (block known malicious IPs, domain filtering)
- [ ] Implement PrivateLink endpoints (S3, SSM, CloudWatch)
- [ ] Deploy AWS Config with required rules (vpc-flow-logs-enabled, etc.)
- [ ] Create Service Control Policies (deny non-encrypted EBS, deny public S3)
- [ ] Test security controls (attempt prohibited actions, verify denials)

**Deliverables**:
- Module: `/modules/aws/security-groups/`
- Module: `/modules/aws/network-firewall/`
- Config: `/policy/aws-config/rules.tf`
- Policies: `/policy/aws-scps/deny-unencrypted.json`
- File: `/docs/runbooks/aws-firewall-rules.md`

**Success Criteria**:
- [ ] Network Firewall blocks test domain (malware.testing.google.com)
- [ ] Config detects non-compliant resource within 5min
- [ ] SCP blocks creation of unencrypted EBS volume
- [ ] tfsec shows 0 high-severity findings

**Dependencies**: 2.1, 2.2 (VPCs exist)

**Risks**:
- Risk: Network Firewall costs → **Mitigation**: Use minimal AZ deployment, document scale-up
- Risk: Config rules too restrictive → **Mitigation**: Start permissive, tighten iteratively

---

#### 2.4 AWS Monitoring & Observability
**Owner**: James | **Priority**: P1 | **Effort**: 10h

**Tasks**:
- [ ] Create CloudWatch dashboard (VPC metrics, NAT, TGW, Network Firewall)
- [ ] Configure CloudWatch Alarms (NAT errors, TGW packet drops, VPN down)
- [ ] Implement EventBridge rules for Config non-compliance
- [ ] Setup SNS topic for alerts (email + future Slack integration)
- [ ] Enable VPC Flow Logs analysis (Athena queries for top talkers)
- [ ] Document SLOs (99.9% NAT availability, <150ms RTT target)
- [ ] Create monitoring runbook (alert triage, escalation)

**Deliverables**:
- Terraform: `/modules/aws/monitoring/` (dashboards, alarms)
- SQL: `/docs/monitoring/flow-logs-queries.sql` (Athena examples)
- File: `/docs/monitoring/aws-slos.md`
- File: `/docs/runbooks/aws-alert-triage.md`

**Success Criteria**:
- [ ] Dashboard loads in <3s, shows real-time metrics
- [ ] Alarm fires when NAT Gateway manually stopped
- [ ] Flow logs queryable via Athena (test query runs <10s)
- [ ] SLO targets documented with measurement method

**Dependencies**: 2.1, 2.2, 2.3 (infrastructure exists)

**Risks**:
- Risk: CloudWatch costs (logs, metrics) → **Mitigation**: Set retention to 7 days for demo
- Risk: Alert fatigue → **Mitigation**: Tune alarm thresholds carefully

---

#### 2.5 Industry Presence - Week 2 Activities
**Owner**: James | **Priority**: P1 | **Effort**: 3h

**Tasks**:
- [ ] LinkedIn Post #2: "AWS Landing Zone architecture - hub-spoke design walkthrough" (include diagram)
- [ ] Share progress in r/aws, r/terraform (non-promotional, ask for feedback)
- [ ] Connect with 5 more cloud professionals
- [ ] Respond to comments/DMs from Week 1 post

**Deliverables**:
- LinkedIn Post #2 (published with Mermaid diagram screenshot)
- Reddit engagement (2 posts)

**Success Criteria**:
- [ ] Post reaches 200+ impressions
- [ ] 1+ technical question/discussion in comments

---

### Phase 3: Azure Landing Zone Implementation (Week 3)
**Duration**: 7 days
**Start**: 2025-10-16 | **End**: 2025-10-22

#### 3.1 Azure Hub VNet & Core Networking
**Owner**: James | **Priority**: P0 | **Effort**: 16h

**Tasks**:
- [ ] Create Terraform module: `modules/azure/vnet-hub`
- [ ] Implement VNet with subnets (GatewaySubnet, AzureFirewallSubnet, mgmt, dmz)
- [ ] Deploy Azure Firewall (Standard SKU for cost)
- [ ] Configure Azure NAT Gateway
- [ ] Implement UDRs (default route → Firewall)
- [ ] Deploy Azure Bastion (optional, cost consideration)
- [ ] Enable NSG Flow Logs → Storage Account + Traffic Analytics
- [ ] Configure DNS (Azure DNS Private Zones or custom)
- [ ] Add outputs (VNet ID, subnet IDs, Firewall IP, etc.)

**Deliverables**:
- Module: `/modules/azure/vnet-hub/`
- Example: `/examples/azure/hub-minimal/`
- File: `/docs/runbooks/azure-provision-hub.md`

**Success Criteria**:
- [ ] `terraform apply` completes in <8min (Firewall takes longer than AWS)
- [ ] NSG Flow Logs visible in Traffic Analytics within 10min
- [ ] Azure Firewall rule tested (block outbound to test domain)
- [ ] tfsec/checkov pass

**Dependencies**: 1.2 (CIDR design), 1.4 (tooling)

**Risks**:
- Risk: Azure Firewall cost ($1.25/hr = ~$900/month) → **Mitigation**: Deploy only during testing, document cost, consider NSG-only variant
- Risk: Bastion cost ($140/month) → **Mitigation**: Make optional, use VM + NSG instead

---

#### 3.2 Azure Spoke VNets & Peering
**Owner**: James | **Priority**: P0 | **Effort**: 12h

**Tasks**:
- [ ] Create Terraform module: `modules/azure/vnet-spoke`
- [ ] Implement VNet peering to hub (bi-directional)
- [ ] Configure UDRs (spoke → hub firewall for internet)
- [ ] Enable NSG Flow Logs per spoke
- [ ] Deploy 3 spoke examples (dev, test, prod)
- [ ] Test connectivity (VM in dev spoke → test spoke via hub firewall)
- [ ] Document spoke provisioning runbook

**Deliverables**:
- Module: `/modules/azure/vnet-spoke/`
- Examples: `/examples/azure/spoke-dev/`, etc.
- File: `/docs/runbooks/azure-provision-spoke.md`

**Success Criteria**:
- [ ] Spoke VNet deploys in <4min
- [ ] Peering established automatically
- [ ] Traffic flows through hub firewall (verified in logs)
- [ ] Module supports NSG customization

**Dependencies**: 3.1 (hub VNet exists)

**Risks**:
- Risk: Peering direction confusion → **Mitigation**: Document clearly, use diagrams
- Risk: UDR misconfiguration breaks connectivity → **Mitigation**: Test incrementally

---

#### 3.3 Azure Security Controls (NSG, ASG, Azure Policy)
**Owner**: James | **Priority**: P0 | **Effort**: 14h

**Tasks**:
- [ ] Create NSG modules (bastion, app-tier, data-tier with ASGs)
- [ ] Configure Azure Firewall rules (application rules, network rules, threat intel)
- [ ] Deploy Private Endpoints (Storage, Key Vault)
- [ ] Implement Azure Policy (deny public endpoints, require encryption, enforce tagging)
- [ ] Configure Management Groups (optional, document for enterprise)
- [ ] Deploy Azure Key Vault for secrets
- [ ] Test security controls (attempt prohibited actions)

**Deliverables**:
- Module: `/modules/azure/network-security-groups/`
- Policies: `/policy/azure-policy/deny-public-endpoints.json`
- File: `/docs/runbooks/azure-firewall-rules.md`

**Success Criteria**:
- [ ] Azure Policy blocks creation of Storage Account with public access
- [ ] Private Endpoint tested (access Blob from VM without public IP)
- [ ] NSG blocks unauthorized traffic (tested with test VMs)
- [ ] checkov passes on all Terraform code

**Dependencies**: 3.1, 3.2 (VNets exist)

**Risks**:
- Risk: Policy too restrictive breaks deployments → **Mitigation**: Test in dev subscription first
- Risk: Private Endpoint DNS complexity → **Mitigation**: Document DNS resolution flow

---

#### 3.4 Azure Monitoring & Observability
**Owner**: James | **Priority**: P1 | **Effort**: 10h

**Tasks**:
- [ ] Configure Azure Monitor workbook (VNet, Firewall, NAT, VPN metrics)
- [ ] Setup Azure Monitor Alerts (firewall threat detected, VPN down, NSG deny spikes)
- [ ] Enable Traffic Analytics (NSG Flow Logs → Log Analytics)
- [ ] Create Log Analytics queries (top talkers, blocked traffic, policy violations)
- [ ] Configure Action Groups (email, future webhook to Slack)
- [ ] Document SLOs (99.9% VNet availability, <150ms RTT)
- [ ] Create monitoring runbook

**Deliverables**:
- Terraform: `/modules/azure/monitoring/`
- KQL: `/docs/monitoring/azure-queries.kql`
- File: `/docs/monitoring/azure-slos.md`
- File: `/docs/runbooks/azure-alert-triage.md`

**Success Criteria**:
- [ ] Workbook displays metrics from all VNets
- [ ] Alert fires when firewall rule manually triggered
- [ ] Traffic Analytics shows topology within 15min
- [ ] KQL queries documented for common scenarios

**Dependencies**: 3.1, 3.2, 3.3 (infrastructure exists)

**Risks**:
- Risk: Log Analytics costs → **Mitigation**: 7-day retention, document scale-up
- Risk: Query complexity → **Mitigation**: Start with simple queries, iterate

---

#### 3.5 Multi-Cloud Considerations & Hybrid Connectivity
**Owner**: James | **Priority**: P2 | **Effort**: 8h

**Tasks**:
- [ ] Document AWS-Azure hybrid connectivity options (VPN, ExpressRoute/Direct Connect)
- [ ] Create Mermaid diagram for hybrid scenario
- [ ] Implement simple VPN between AWS VGW and Azure VPN Gateway (optional, cost)
- [ ] Document IPsec parameters and troubleshooting
- [ ] Create runbook for hybrid connectivity

**Deliverables**:
- File: `/docs/architecture/hybrid-connectivity.md`
- Diagram: `/diag/aws-azure-vpn.mmd`
- Module: `/modules/hybrid/vpn-tunnel/` (optional)
- File: `/docs/runbooks/hybrid-vpn-troubleshooting.md`

**Success Criteria**:
- [ ] Diagram clearly shows hybrid architecture
- [ ] If implemented: VPN tunnel establishes, traffic flows
- [ ] Documentation covers cost implications ($70-100/month for VPN gateways)

**Dependencies**: 2.1, 3.1 (both hubs exist)

**Risks**:
- Risk: VPN cost not justified for demo → **Mitigation**: Document design, make implementation optional
- Risk: VPN troubleshooting delays → **Mitigation**: Timebox to 4h, document known issues

---

#### 3.6 Industry Presence - Week 3 Activities
**Owner**: James | **Priority**: P1 | **Effort**: 3h

**Tasks**:
- [ ] LinkedIn Post #3: "Azure Landing Zone - comparing AWS vs Azure approaches"
- [ ] Engage in 3 LinkedIn discussions (comment on architects' posts)
- [ ] Share Azure module in r/azure, r/devops
- [ ] Connect with 5 Azure-focused professionals

**Deliverables**:
- LinkedIn Post #3 (comparative analysis)
- Community engagement

**Success Criteria**:
- [ ] Post reaches 250+ impressions
- [ ] 1+ discussion about AWS vs Azure trade-offs

---

### Phase 4: Security Automation & Orchestration (Week 4)
**Duration**: 7 days
**Start**: 2025-10-23 | **End**: 2025-10-29

#### 4.1 AWS GuardDuty → EventBridge → Lambda Auto-Block
**Owner**: James | **Priority**: P0 | **Effort**: 14h

**Tasks**:
- [ ] Enable GuardDuty in AWS account
- [ ] Create Lambda function (Python 3.11) for IP blocking
- [ ] Implement logic: parse GuardDuty finding → extract malicious IP → update NACL/Security Group
- [ ] Add TTL/auto-expiry (tag with timestamp, scheduled Lambda to cleanup)
- [ ] Implement allowlist (never block trusted IPs)
- [ ] Add dry-run mode (log action without execution)
- [ ] Configure EventBridge rule (GuardDuty finding → Lambda)
- [ ] Deploy SNS notifications (GuardDuty finding + auto-block action)
- [ ] Create DynamoDB table for audit log (IP, timestamp, finding ID, action)
- [ ] Write unit tests (pytest) for Lambda logic
- [ ] Create manual unblock runbook

**Deliverables**:
- Code: `/automation/aws-guardduty-autoblock/lambda_function.py`
- Terraform: `/automation/aws-guardduty-autoblock/terraform/`
- Tests: `/automation/aws-guardduty-autoblock/tests/`
- File: `/docs/runbooks/aws-unblock-ip.md`
- File: `/automation/aws-guardduty-autoblock/README.md`

**Success Criteria**:
- [ ] Simulated GuardDuty finding triggers Lambda within 30s
- [ ] Malicious IP added to NACL deny rule
- [ ] TTL cleanup tested (IP removed after expiry)
- [ ] Unit tests achieve >80% code coverage
- [ ] Dry-run mode verified (no actual changes)

**Dependencies**: 2.1, 2.2 (AWS infrastructure exists)

**Risks**:
- Risk: Lambda timeout (15min max) → **Mitigation**: Optimize for <10s execution
- Risk: NACL rule limit (20 rules) → **Mitigation**: Document limit, consider SG instead
- Risk: False positives block legitimate traffic → **Mitigation**: Allowlist, dry-run default

---

#### 4.2 Azure Defender/Sentinel → Logic App/Function Auto-Block
**Owner**: James | **Priority**: P0 | **Effort**: 14h

**Tasks**:
- [ ] Enable Microsoft Defender for Cloud (Free tier)
- [ ] Create Azure Function (Python) or Logic App for IP blocking
- [ ] Implement logic: parse Defender alert → extract IP → update NSG deny rule
- [ ] Add TTL/auto-expiry (tag with timestamp, scheduled cleanup)
- [ ] Implement allowlist
- [ ] Add dry-run mode
- [ ] Configure alert action group (Defender → Function/Logic App)
- [ ] Deploy notification (email + future Teams webhook)
- [ ] Create Storage Table for audit log
- [ ] Write unit tests (pytest) for Function
- [ ] Create manual unblock runbook

**Deliverables**:
- Code: `/automation/azure-defender-autoblock/function_app.py` or Logic App JSON
- Terraform: `/automation/azure-defender-autoblock/terraform/`
- Tests: `/automation/azure-defender-autoblock/tests/`
- File: `/docs/runbooks/azure-unblock-ip.md`
- File: `/automation/azure-defender-autoblock/README.md`

**Success Criteria**:
- [ ] Simulated Defender alert triggers Function within 30s
- [ ] Malicious IP added to NSG deny rule
- [ ] TTL cleanup tested
- [ ] Unit tests achieve >80% coverage
- [ ] Logic App workflow diagram included (if using Logic App)

**Dependencies**: 3.1, 3.2 (Azure infrastructure exists)

**Risks**:
- Risk: Defender Free tier limited alerts → **Mitigation**: Document upgrade path, use test alerts
- Risk: NSG rule limit (200 inbound) → **Mitigation**: Document limit, rotate old rules
- Risk: Logic App cost vs Function → **Mitigation**: Compare, document choice rationale

---

#### 4.3 Automation Testing & Validation
**Owner**: James | **Priority**: P0 | **Effort**: 8h

**Tasks**:
- [ ] Create test harness for triggering simulated findings
- [ ] Test AWS automation end-to-end (inject test finding → verify block)
- [ ] Test Azure automation end-to-end
- [ ] Validate TTL cleanup (schedule to 5min for testing)
- [ ] Test allowlist (attempt to block allowlisted IP, verify skip)
- [ ] Test dry-run mode (verify no changes, only logs)
- [ ] Performance test (100 concurrent findings, measure response time)
- [ ] Document test results and metrics

**Deliverables**:
- Tests: `/automation/tests/integration/` (end-to-end test scripts)
- File: `/docs/testing/automation-test-results.md`

**Success Criteria**:
- [ ] 100% of test scenarios pass
- [ ] Response time <30s from finding to block
- [ ] No false positives in test runs
- [ ] Documented evidence (screenshots, logs)

**Dependencies**: 4.1, 4.2 (automation deployed)

**Risks**:
- Risk: Test environment cost → **Mitigation**: Use dev spokes, destroy after testing
- Risk: Flaky tests → **Mitigation**: Add retries, document known issues

---

#### 4.4 Industry Presence - Week 4 Activities
**Owner**: James | **Priority**: P1 | **Effort**: 4h

**Tasks**:
- [ ] LinkedIn Post #4: "Event-driven security automation - GuardDuty to auto-block in 30s" (include architecture diagram + demo video)
- [ ] Create 2-min demo video (screen recording: trigger finding → auto-block → show logs)
- [ ] Share in r/AWSsecurity, r/Azure security communities
- [ ] Connect with 5 security-focused professionals
- [ ] Engage with hiring managers at target companies

**Deliverables**:
- LinkedIn Post #4 (with video link)
- Video: `/docs/demo/guardduty-autoblock-demo.mp4` (uploaded to YouTube/LinkedIn)
- Community posts

**Success Criteria**:
- [ ] Post reaches 300+ impressions
- [ ] Video viewed 50+ times
- [ ] 2+ technical discussions in comments

---

### Phase 5: Hardening, Testing & Documentation (Week 5)
**Duration**: 7 days
**Start**: 2025-10-30 | **End**: 2025-11-05

#### 5.1 Infrastructure Hardening & Security Scanning
**Owner**: James | **Priority**: P0 | **Effort**: 12h

**Tasks**:
- [ ] Run tfsec on all Terraform modules, remediate findings
- [ ] Run checkov on all code, achieve 90+ score
- [ ] Implement AWS Config conformance packs (CIS AWS Foundations)
- [ ] Implement Azure Policy initiative (CIS Azure Foundations)
- [ ] Enable AWS GuardDuty findings export to S3
- [ ] Enable Azure Defender recommendations review
- [ ] Rotate all secrets (API keys, passwords) to AWS Secrets Manager / Key Vault
- [ ] Enable AWS CloudTrail + Azure Activity Log for audit
- [ ] Configure S3 bucket policies (deny insecure transport)
- [ ] Configure Storage Account firewall rules
- [ ] Document hardening checklist

**Deliverables**:
- File: `/docs/security/hardening-checklist.md`
- File: `/docs/security/scanning-results.md` (tfsec, checkov reports)
- Updated Terraform code (security fixes applied)

**Success Criteria**:
- [ ] tfsec: 0 high/critical findings across all modules
- [ ] checkov: 90+ score on all code
- [ ] Config/Policy: 100% compliant resources
- [ ] All secrets stored in vaults, no hardcoded credentials

**Dependencies**: All previous phases (infrastructure exists)

**Risks**:
- Risk: Security findings require architecture changes → **Mitigation**: Prioritize high/critical, document medium/low
- Risk: Config/Policy rules break existing resources → **Mitigation**: Test in dev, apply to prod

---

#### 5.2 Comprehensive Testing Suite
**Owner**: James | **Priority**: P0 | **Effort**: 14h

**Tasks**:
- [ ] Create Terraform validation tests (syntax, formatting)
- [ ] Implement tflint tests (module best practices)
- [ ] Write integration tests (deploy → validate → destroy)
- [ ] Test cost estimation (Infracost or terraform-cost-estimation)
- [ ] Create smoke tests (basic connectivity, DNS resolution)
- [ ] Test disaster recovery (delete resource, validate auto-remediation or alerts)
- [ ] Test scaling scenarios (add 4th spoke, validate routing)
- [ ] Document test procedures and results
- [ ] Configure GitHub Actions to run tests on PR

**Deliverables**:
- Tests: `/tests/` (unit, integration, smoke)
- CI Config: `/.github/workflows/test.yml`
- File: `/docs/testing/test-strategy.md`
- File: `/docs/testing/test-results.md`

**Success Criteria**:
- [ ] All tests pass in CI pipeline
- [ ] Integration tests complete in <15min
- [ ] Cost estimation included in PR comments (GitHub Action)
- [ ] Test coverage documented (% of modules tested)

**Dependencies**: All infrastructure modules complete

**Risks**:
- Risk: Integration tests take too long → **Mitigation**: Parallelize, use smaller deployments
- Risk: Flaky tests in CI → **Mitigation**: Add retries, document known issues

---

#### 5.3 Documentation Completion
**Owner**: James | **Priority**: P0 | **Effort**: 16h

**Tasks**:
- [ ] Complete README.md (overview, quick start, features, architecture)
- [ ] Write deployment guides (AWS step-by-step, Azure step-by-step)
- [ ] Complete all module READMEs (inputs, outputs, examples)
- [ ] Create architecture decision records (ADRs) for key choices
- [ ] Write runbooks:
  - Provisioning new spoke
  - Firewall rule changes
  - Break-glass access
  - Incident response
  - Backup and recovery
  - Cost optimization
- [ ] Document troubleshooting (common errors, solutions)
- [ ] Create FAQ
- [ ] Write CHANGELOG.md
- [ ] Proofread all documentation (grammar, clarity, formatting)

**Deliverables**:
- File: `/README.md` (comprehensive)
- Files: `/docs/deployment/aws-deploy.md`, `/docs/deployment/azure-deploy.md`
- Files: `/docs/runbooks/*.md` (8+ runbooks)
- Files: `/docs/architecture/adr/*.md` (5+ ADRs)
- File: `/docs/FAQ.md`
- File: `/docs/TROUBLESHOOTING.md`
- File: `/CHANGELOG.md`

**Success Criteria**:
- [ ] README includes quick start (user can deploy in <30min)
- [ ] All Terraform modules have usage examples
- [ ] Runbooks tested by external reviewer (friend/colleague)
- [ ] Documentation passes markdown lint
- [ ] Diagrams render correctly on GitHub

**Dependencies**: All technical work complete

**Risks**:
- Risk: Documentation overwhelming → **Mitigation**: Prioritize quick start + runbooks, defer deep-dives
- Risk: Documentation diverges from code → **Mitigation**: Generate docs from Terraform outputs

---

#### 5.4 Cost Optimization & Resource Cleanup
**Owner**: James | **Priority**: P1 | **Effort**: 6h

**Tasks**:
- [ ] Audit AWS resources (identify idle resources)
- [ ] Audit Azure resources
- [ ] Implement Terraform destroy automation (scheduled cleanup)
- [ ] Document cost breakdown (per module, per environment)
- [ ] Create cost optimization recommendations
- [ ] Configure AWS Budget alerts ($50/month threshold)
- [ ] Configure Azure Budget alerts
- [ ] Tag all resources for cost allocation
- [ ] Test destroy process (ensure clean teardown)

**Deliverables**:
- File: `/docs/cost/cost-breakdown.md`
- File: `/docs/cost/optimization-tips.md`
- Terraform: `/scripts/destroy-all.sh`

**Success Criteria**:
- [ ] Monthly cost estimate documented (<$200/month for full deployment)
- [ ] Destroy script tested (all resources cleaned up)
- [ ] Budget alerts configured and tested
- [ ] Cost tags applied to 100% of resources

**Dependencies**: All infrastructure deployed

**Risks**:
- Risk: Lingering resources accrue cost → **Mitigation**: Scheduled destroy script, budget alerts

---

#### 5.5 Industry Presence - Week 5 Activities
**Owner**: James | **Priority**: P1 | **Effort**: 4h

**Tasks**:
- [ ] LinkedIn Post #5: "Lessons learned - building production-grade cloud landing zones"
- [ ] Write short blog post (Medium/dev.to): "AWS vs Azure Network Landing Zones - A Practitioner's Comparison"
- [ ] Share blog in communities
- [ ] Connect with 5 more professionals (target platform engineers, SREs)
- [ ] Request LinkedIn recommendations from colleagues/managers

**Deliverables**:
- LinkedIn Post #5
- Blog post (published on Medium)
- 2+ LinkedIn recommendations received

**Success Criteria**:
- [ ] Blog post receives 100+ views in first week
- [ ] Post reaches 250+ impressions
- [ ] 1+ recommendation published

---

### Phase 6: Case Studies, Content & Launch (Week 6)
**Duration**: 7 days
**Start**: 2025-11-06 | **End**: 2025-11-12

#### 6.1 Case Study #1: Enterprise AWS Migration
**Owner**: James | **Priority**: P0 | **Effort**: 10h

**Tasks**:
- [ ] Define fictional scenario (e.g., "FinTech migrating on-prem DC to AWS")
- [ ] Document business context (drivers, constraints, requirements)
- [ ] Describe solution architecture (hub-spoke, security controls, automation)
- [ ] Detail implementation approach (phased migration, cutover strategy)
- [ ] Quantify outcomes (cost savings, security improvements, deployment speed)
- [ ] Include diagrams (before/after architecture)
- [ ] Add lessons learned and recommendations
- [ ] Proofread and format professionally

**Deliverables**:
- File: `/docs/case-studies/aws-enterprise-migration.md`
- Diagrams: `/diag/case-study-1-*.mmd`

**Success Criteria**:
- [ ] Case study is 2000-3000 words
- [ ] Includes quantifiable metrics (e.g., "60% cost reduction", "10x faster deployments")
- [ ] Demonstrates understanding of enterprise requirements (compliance, governance)
- [ ] Reviewed by external professional for realism

**Dependencies**: All AWS work complete (for credibility)

---

#### 6.2 Case Study #2: Azure Zero-Trust Network
**Owner**: James | **Priority**: P0 | **Effort**: 10h

**Tasks**:
- [ ] Define scenario (e.g., "Healthcare SaaS implementing Zero Trust")
- [ ] Document business context (regulatory compliance, threat landscape)
- [ ] Describe solution (NSGs, Private Endpoints, Azure Policy, Defender)
- [ ] Detail Zero Trust principles applied (verify explicitly, least privilege, assume breach)
- [ ] Quantify outcomes (reduced attack surface, compliance achievement)
- [ ] Include diagrams (Zero Trust architecture)
- [ ] Add lessons learned
- [ ] Proofread and format

**Deliverables**:
- File: `/docs/case-studies/azure-zero-trust.md`
- Diagrams: `/diag/case-study-2-*.mmd`

**Success Criteria**:
- [ ] Case study is 2000-3000 words
- [ ] Explicitly maps to Zero Trust principles
- [ ] Includes compliance references (HIPAA, GDPR)
- [ ] Reviewed externally

**Dependencies**: All Azure work complete

---

#### 6.3 Repository Polish & Launch Preparation
**Owner**: James | **Priority**: P0 | **Effort**: 8h

**Tasks**:
- [ ] Create high-quality README badges (build status, license, stars)
- [ ] Design banner/logo for repository (Canva or similar)
- [ ] Record comprehensive demo video (10-15min walkthrough)
- [ ] Create GIF animations for key features (deployment, auto-block)
- [ ] Optimize for GitHub search (topics, description, tags)
- [ ] Create CONTRIBUTING.md (how to contribute, PR guidelines)
- [ ] Setup GitHub Discussions or enable Issues
- [ ] Configure repository settings (About section, website link)
- [ ] Create release v1.0.0 with changelog
- [ ] Test repository from external perspective (clone fresh, follow README)

**Deliverables**:
- Updated `/README.md` (polished, with visuals)
- Video: `/docs/demo/full-walkthrough.mp4` (YouTube)
- Images: `/docs/images/` (screenshots, diagrams)
- GitHub Release: v1.0.0

**Success Criteria**:
- [ ] README renders beautifully on GitHub (images, formatting)
- [ ] Demo video is professional quality (clear audio, smooth transitions)
- [ ] External tester can deploy successfully following README
- [ ] Repository stars increase to 20+ within launch week

**Dependencies**: All technical work, documentation, case studies complete

**Risks**:
- Risk: Demo video takes excessive time → **Mitigation**: Use simple screen recording tool (OBS), 1-2 takes max
- Risk: README too long → **Mitigation**: Move details to /docs, keep README concise

---

#### 6.4 Open Source Contribution & Community Engagement
**Owner**: James | **Priority**: P1 | **Effort**: 6h

**Tasks**:
- [ ] Identify 2-3 related OSS projects (Terraform AWS modules, Azure Quickstarts)
- [ ] Contribute meaningful PR (bug fix, documentation improvement, test)
- [ ] Link back to cloud-netsec-blueprints in PR description (subtly)
- [ ] Engage in GitHub Discussions on popular repos
- [ ] Answer questions on Stack Overflow (Terraform, AWS, Azure networking tags)
- [ ] Share project in curated lists (awesome-terraform, awesome-azure)

**Deliverables**:
- 2+ merged PRs to external projects
- 3+ Stack Overflow answers
- Submissions to awesome-* lists

**Success Criteria**:
- [ ] PRs merged and acknowledged
- [ ] Stack Overflow answers upvoted
- [ ] cloud-netsec-blueprints linked from 1+ external resource

**Dependencies**: Repository complete and public

---

#### 6.5 LinkedIn Launch Campaign & Networking Blitz
**Owner**: James | **Priority**: P0 | **Effort**: 8h

**Tasks**:
- [ ] LinkedIn Post #6: "Launching Cloud Network Blueprints - production-grade AWS/Azure landing zones" (link to repo, demo video)
- [ ] Schedule 3 follow-up posts (week 7-9): specific features, use cases, hiring availability
- [ ] Share in 5+ LinkedIn groups (Cloud Architects, DevOps, Platform Engineering)
- [ ] Direct message 10 hiring managers at target companies (personalized, link to repo)
- [ ] Request informational interviews with 3 senior architects
- [ ] Update resume with project (quantify: "Built multi-cloud landing zones supporting 100+ resources, <30s threat response")
- [ ] Apply to 10 target jobs (use case studies as cover letter supplement)
- [ ] Prepare interview talking points (project challenges, decisions, outcomes)

**Deliverables**:
- LinkedIn Post #6 (launch announcement)
- Updated resume (PDF)
- Job applications submitted (tracked in spreadsheet)
- File: `/docs/career/interview-talking-points.md`

**Success Criteria**:
- [ ] Launch post reaches 500+ impressions
- [ ] 10+ new GitHub stars from LinkedIn traffic
- [ ] 3+ DMs from hiring managers or recruiters
- [ ] 5+ job applications submitted
- [ ] 1+ informational interview scheduled

**Dependencies**: Repository polished and launched

**Risks**:
- Risk: LinkedIn post flops → **Mitigation**: Boost post ($20), tag relevant people/companies
- Risk: No immediate job responses → **Mitigation**: Expect 2-4 week lag, continue networking

---

### Phase 7: Post-Launch Optimization (Week 7-8, Ongoing)
**Duration**: Ongoing
**Start**: 2025-11-13+

#### 7.1 Monitoring & Iteration
**Owner**: James | **Priority**: P2 | **Effort**: 2h/week

**Tasks**:
- [ ] Monitor GitHub analytics (stars, forks, traffic sources)
- [ ] Respond to GitHub Issues within 24h
- [ ] Review and merge external PRs
- [ ] Update documentation based on user feedback
- [ ] Add feature requests to backlog (prioritize high-impact, low-effort)
- [ ] Share user testimonials/usage on LinkedIn

**Success Criteria**:
- [ ] Maintain <24h issue response time
- [ ] Grow to 100+ stars within 30 days
- [ ] 1+ external contribution merged

---

#### 7.2 Interview Preparation & Follow-Through
**Owner**: James | **Priority**: P0 | **Effort**: Ongoing

**Tasks**:
- [ ] Prepare technical deep-dive presentation (30min version for interviews)
- [ ] Practice whiteboarding network architectures
- [ ] Prepare answers to common interview questions using project examples
- [ ] Create leave-behind document (1-pager: project summary + outcomes)
- [ ] Follow up on applications weekly
- [ ] Track interview outcomes and iterate approach

**Success Criteria**:
- [ ] 5+ interviews scheduled within 4 weeks of launch
- [ ] Able to deliver 30min technical presentation without notes
- [ ] 1+ job offer within 8 weeks

---

## Risk Register

| Risk ID | Risk Description | Impact | Probability | Mitigation Strategy | Owner |
|---------|-----------------|--------|-------------|-------------------|--------|
| R-001 | 6-week timeline too aggressive, quality suffers | High | High | Prioritize MVP features, defer nice-to-haves; build buffer into critical path; daily progress tracking | James |
| R-002 | Cloud costs exceed budget ($500+ AWS+Azure) | Medium | Medium | Destroy resources nightly; use smallest SKUs; set budget alerts at $100, $200; consider free tier only | James |
| R-003 | Azure Firewall cost prohibitive ($900/month) | Medium | High | Deploy only during testing; document cost clearly; create NSG-only variant; consider Firewall Basic SKU (if available) | James |
| R-004 | Technical blockers (Terraform bugs, API limits) | High | Medium | Allocate 20% buffer time; engage vendor support early; document workarounds; have fallback designs | James |
| R-005 | Scope creep (feature additions delay completion) | High | Medium | Strict scope control; defer enhancements to v2.0; use "must-have" vs "nice-to-have" criteria | James |
| R-006 | Security automation false positives | Medium | Medium | Implement allowlist, dry-run mode; extensive testing; clear unblock runbook | James |
| R-007 | Documentation lags behind code | Medium | High | Write docs alongside code; use ADRs for decisions; allocate dedicated Week 5 time | James |
| R-008 | LinkedIn/networking yields no responses | Medium | Low | Multi-channel approach (Reddit, Twitter, Stack Overflow); target 50+ connections, not 10; optimize headline/profile | James |
| R-009 | Burnout from aggressive schedule | High | Medium | Schedule rest days; limit to 6h/day focused work; celebrate weekly milestones; maintain exercise routine | James |
| R-010 | GitHub repo gets little traction | Medium | Medium | Invest in launch (boost post, share in 10+ communities); create demo video; submit to newsletters (DevOps Weekly) | James |
| R-011 | Integration test failures delay Week 5 | Medium | Medium | Write tests incrementally (Weeks 2-4); run CI frequently; allocate 2 days buffer in Week 5 | James |
| R-012 | Multi-cloud complexity creates inconsistencies | Medium | Medium | Document design patterns per cloud; reuse structure (modules/aws/* mirrors modules/azure/*); cross-review | James |

---

## Success Metrics & KPIs

### Technical Excellence
- [ ] **Code Quality**: tfsec 0 critical, checkov 90+ score across all modules
- [ ] **Deployment Speed**: Hub deploys in <5min, spoke in <3min
- [ ] **Automation Speed**: Threat detection → auto-block in <30s
- [ ] **Test Coverage**: 80%+ unit test coverage for Lambda/Functions, 100% module integration tests
- [ ] **Documentation Completeness**: 100% of modules have README, 8+ runbooks, 2 case studies

### Industry Impact
- [ ] **GitHub Stars**: 100+ within 30 days of launch
- [ ] **Traffic**: 1000+ unique visitors to repo in first month
- [ ] **Community Engagement**: 5+ external Issues/PRs, 20+ discussions
- [ ] **LinkedIn Impressions**: 2000+ cumulative across 6 posts
- [ ] **Professional Network**: 50+ new connections, 5+ meaningful conversations with hiring managers

### Career Outcomes
- [ ] **Interview Pipeline**: 5+ interviews within 4 weeks of launch
- [ ] **Resume Impact**: Project cited in 100% of cover letters and interviews
- [ ] **Recruiter Inbound**: 3+ recruiter messages referencing the project
- [ ] **Job Offers**: 1+ offer within 8 weeks (AUD $140k-$180k range)
- [ ] **Long-term**: Established as credible cloud network architect in community

---

## Dependencies & Critical Path

### Critical Path (must complete sequentially)
1. **Week 1**: 1.1 Repo Setup → 1.2 Network Design → 1.4 Tooling
2. **Week 2**: 2.1 AWS Hub → 2.2 AWS Spokes → 2.3 AWS Security
3. **Week 3**: 3.1 Azure Hub → 3.2 Azure Spokes → 3.3 Azure Security
4. **Week 4**: 4.1 AWS Automation → 4.2 Azure Automation → 4.3 Testing
5. **Week 5**: 5.1 Hardening → 5.2 Testing → 5.3 Documentation
6. **Week 6**: 6.1 Case Study 1 → 6.2 Case Study 2 → 6.3 Polish → 6.5 Launch

### Parallel Tracks
- **Industry Presence** (Weeks 1-6): Runs parallel to technical work, 3-4h/week
- **Monitoring** (Weeks 2-4): Implemented alongside infrastructure, not blocking
- **Hybrid Connectivity** (Week 3): Optional, can defer to Week 7 if needed

### Key Decision Points
- **Day 5**: Finalize CIDR design (blocks Week 2 AWS, Week 3 Azure)
- **Day 10**: Decide Azure Firewall deployment (impacts Week 3 schedule/cost)
- **Day 15**: Commit to VPN hybrid connectivity or document-only (impacts Week 3.5)
- **Day 20**: Choose Azure Function vs Logic App for automation (impacts Week 4.2)
- **Day 30**: Assess schedule health, defer optional features if behind

---

## Resource Plan

### Human Resources
- **Primary Contributor**: James (sole developer)
- **Estimated Effort**: 240-300 hours over 6 weeks (40-50h/week)
- **External Review**: 2-3 peer reviews (architects, security engineers) for validation

### Cloud Resources (Estimated Monthly Cost)
**AWS**:
- VPC, Subnets, Route Tables: Free
- NAT Gateway (2x): ~$65/month (or $32 for single NAT)
- Transit Gateway: ~$35/month
- Network Firewall: ~$415/month (1 AZ) - **Deploy only during testing**
- GuardDuty: ~$10/month (30-day trial free)
- EC2 test instances (t3.micro): ~$15/month
- CloudWatch Logs (7-day retention): ~$10/month
- **Total AWS**: ~$550/month (or ~$135 without Network Firewall full-time)

**Azure**:
- VNets, Subnets, NSGs: Free
- Azure Firewall (Standard): ~$900/month - **Deploy only during testing**
- Azure NAT Gateway: ~$45/month
- Bastion (optional): ~$140/month - **Skip or deploy minimally**
- Defender for Cloud: Free tier
- VMs (B1s): ~$10/month
- Log Analytics (7-day): ~$15/month
- **Total Azure**: ~$1010/month (or ~$70 without Firewall/Bastion full-time)

**Cost Optimization Strategy**:
1. Deploy firewalls only during Week 2-4 testing (16 days = ~$700 total)
2. Use single NAT Gateway per cloud (vs HA) for dev
3. Destroy all resources nightly (except testing days)
4. Estimated **Total Project Cost**: $800-$1000 (vs $9000+ for full 6-week deployment)

### Tools & Software (Free/OSS)
- Terraform, tflint, tfsec, checkov
- AWS CLI, Azure CLI
- VSCode with extensions
- GitHub Actions (free tier: 2000 min/month)
- Python 3.11 with pytest
- Mermaid for diagrams

---

## Communication Plan

### Internal (Solo Project)
- **Daily Log**: End-of-day commit message with progress summary
- **Weekly Retrospective**: Friday evening - review week's outcomes, adjust next week's plan
- **Decision Log**: Document key technical decisions in `/docs/architecture/adr/`

### External (Community & Network)
- **LinkedIn Posts**: Weekly (Thursdays, 10am AEST for visibility)
- **Reddit/Community**: Bi-weekly (Tuesdays)
- **GitHub Updates**: Release notes for major milestones
- **Networking DMs**: 5 new connections/week (Mondays)

### Stakeholder Engagement
- **Peer Reviewers**: Request feedback Weeks 3, 5, 6 (architecture, code, case studies)
- **Hiring Managers**: Direct outreach Week 6 with launch announcement
- **Recruiters**: Update profile Week 1, share project Week 6

---

## Quality Assurance

### Code Quality Gates
- [ ] All Terraform code passes `terraform validate`
- [ ] tflint passes with 0 errors
- [ ] tfsec: 0 critical, <5 high findings
- [ ] checkov: 90+ score per module
- [ ] Pre-commit hooks enforced

### Testing Strategy
- **Unit Tests**: Lambda/Function code (pytest, 80%+ coverage)
- **Integration Tests**: Deploy → validate → destroy (per module)
- **Smoke Tests**: Quick connectivity/functionality checks
- **Security Tests**: tfsec, checkov, manual penetration attempts
- **Cost Tests**: Infracost estimates on PR

### Documentation Quality
- [ ] All markdown passes markdownlint
- [ ] All Terraform modules have README with examples
- [ ] All diagrams render on GitHub
- [ ] External reviewer can deploy successfully
- [ ] No broken links in documentation

### Peer Review
- **Architecture Review** (Week 3): External cloud architect reviews network design
- **Security Review** (Week 5): External security engineer reviews threat model + automation
- **Usability Review** (Week 6): External user attempts deployment, provides feedback

---

## Assumptions & Constraints

### Assumptions
1. James has intermediate Terraform experience (can write modules, not expert)
2. AWS and Azure accounts are available with billing enabled
3. Budget approved for $1000 cloud spend over 6 weeks
4. James can dedicate 40-50h/week for 6 weeks
5. No major life/work disruptions during project period
6. External peer reviewers available for feedback
7. LinkedIn network has 200+ connections (for content distribution)

### Constraints
1. **Time**: Hard 6-week deadline (job application timing)
2. **Budget**: $1000 total cloud spend (requires optimization)
3. **Scope**: AWS + Azure only (no GCP, no Kubernetes)
4. **Resources**: Solo contributor (no team)
5. **Tooling**: Open source only (no paid SaaS)
6. **Compliance**: Demonstrative only (not production-certified for SOC2/PCI)

---

## Change Management

### Scope Change Process
1. Evaluate impact on critical path and timeline
2. Assess value (must-have vs nice-to-have)
3. If nice-to-have: defer to backlog
4. If must-have: identify tasks to descope or schedule slip
5. Document decision in `/docs/architecture/adr/`

### Schedule Adjustments
- **Weekly Review**: Friday retrospective assesses if on track
- **Buffer Utilization**: Week 5 has 2-day buffer for slippage
- **Defer Criteria**: If >3 days behind by Week 4, defer hybrid connectivity and 1 case study

### Quality Trade-offs
- **Non-negotiable**: Security (tfsec/checkov must pass), Core functionality (hub-spoke works)
- **Flexible**: Number of spokes (3 vs 2), Hybrid connectivity (document vs implement), Advanced monitoring (dashboards vs basic alarms)

---

## Lessons Learned (Post-Project)

### To Be Completed After Week 6
- [ ] What went well?
- [ ] What could be improved?
- [ ] Technical challenges and resolutions
- [ ] Timeline accuracy (estimated vs actual)
- [ ] Cost accuracy (estimated vs actual)
- [ ] Unexpected learnings
- [ ] Recommendations for future projects

---

## Appendices

### A. Detailed Task Checklists
See Phase breakdowns above for granular tasks.

### B. Technology Stack
**Infrastructure as Code**:
- Terraform 1.6+ (primary)
- Bicep (Azure reference)
- CloudFormation (AWS reference)

**Cloud Platforms**:
- AWS (us-east-1 primary region)
- Azure (Australia East primary region for locale relevance)

**Automation & Scripting**:
- Python 3.11 (Lambda, Azure Functions)
- Bash (CI/CD, utility scripts)

**Security & Compliance**:
- tfsec, checkov (static analysis)
- AWS Config, Azure Policy (runtime compliance)
- GuardDuty, Defender for Cloud (threat detection)

**Monitoring & Observability**:
- AWS CloudWatch (metrics, logs, dashboards)
- Azure Monitor (metrics, Log Analytics, workbooks)
- EventBridge, Logic Apps (event orchestration)

**CI/CD**:
- GitHub Actions (build, test, security scan)
- Pre-commit hooks (local validation)

**Documentation**:
- Markdown (docs)
- Mermaid (diagrams)
- Terraform-docs (module documentation generation)

### C. Reference Architecture Patterns
- **Hub-Spoke Topology**: Centralized shared services, isolated workload spokes
- **Zero Trust Principles**: Verify explicitly, least privilege, assume breach
- **Event-Driven Automation**: Detect → Orchestrate → Remediate → Audit
- **Infrastructure as Code**: Declarative, version-controlled, automated
- **Observability**: Logs, metrics, traces, SLOs

### D. Compliance & Standards References
- **CIS AWS Foundations Benchmark** v1.5
- **CIS Azure Foundations Benchmark** v2.0
- **NIST Cybersecurity Framework** (Identify, Protect, Detect, Respond, Recover)
- **AWS Well-Architected Framework** (Security, Reliability, Operational Excellence)
- **Azure Well-Architected Framework**

### E. Target Job Titles & Companies
**Job Titles**:
- Cloud Network Architect
- Senior Platform Engineer
- Cloud Security Engineer
- Site Reliability Engineer (SRE) - Infrastructure
- Solutions Architect - Cloud
- DevOps Engineer - Infrastructure

**Target Companies (Australia)**:
- Atlassian, Canva, Afterpay (tech leaders)
- Commonwealth Bank, Westpac, NAB (financial services)
- Telstra, Optus (telecommunications)
- AWS, Microsoft Azure (cloud providers - Professional Services)
- Accenture, Deloitte, PwC (consulting - cloud practices)
- Seek, REA Group (tech product companies)

### F. LinkedIn Content Calendar

| Week | Date | Post Topic | Content Type | Call to Action |
|------|------|------------|--------------|----------------|
| 1 | 2025-10-02 | Project announcement | Text + repo link | Follow journey, share experiences |
| 2 | 2025-10-09 | AWS hub-spoke architecture | Diagram + explanation | Ask for feedback on design |
| 3 | 2025-10-16 | AWS vs Azure comparison | Text + comparison table | Share your multi-cloud experiences |
| 4 | 2025-10-23 | Security automation demo | Video + architecture | Watch demo, discuss use cases |
| 5 | 2025-10-30 | Lessons learned | Text (storytelling) | Share your automation wins/fails |
| 6 | 2025-11-06 | Launch announcement | Video + repo + case studies | Star repo, apply for roles, connect |
| 7 | 2025-11-13 | Case study deep-dive | Long-form + diagrams | Hiring managers: let's talk |
| 8 | 2025-11-20 | Open to opportunities | Professional headshot + summary | Recruiters: reach out |

---

## Project Approval & Sign-off

**Project Plan Version**: 1.0
**Date**: 2025-10-02
**Prepared By**: James (Project Manager & Lead Engineer)
**Approved By**: James (Solo Project - Self-Approval)

**Acknowledgments**:
- This is an aggressive timeline requiring sustained focus and discipline
- Quality must not be sacrificed for speed - defer features if necessary
- Career outcome success depends on both technical excellence AND networking/content strategy
- Budget management critical to avoid overspend - destroy resources nightly

**Commitment**:
I commit to executing this project plan with professionalism, maintaining high code and documentation quality, engaging authentically with the community, and using this as a stepping stone to a rewarding cloud architecture career.

---

**Next Steps**:
1. ✅ Review and approve project plan
2. [ ] Setup development environment (Day 1, Task 1.4)
3. [ ] Initialize GitHub repository (Day 1, Task 1.1)
4. [ ] Begin network architecture design (Day 1-2, Task 1.2)
5. [ ] Update LinkedIn profile and publish Post #1 (Day 2, Task 1.5)

---

*This project plan is a living document and will be updated weekly with progress, lessons learned, and adjustments. All updates will be tracked in CHANGELOG.md.*
