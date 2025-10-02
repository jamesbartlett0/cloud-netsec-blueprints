# Network Architecture Design

## Executive Summary

This document defines the network architecture for a multi-cloud hub-spoke topology spanning AWS and Azure. The design prioritizes:
- **Direct spoke-to-spoke routing** for optimal performance
- **Centralized internet egress** via hub for security and cost efficiency
- **Cross-cloud connectivity** via IPsec VPN with merged routing domains
- **Scalability** to support 100+ resources per spoke with room for growth

## Subnet Segmentation Philosophy

### Four-Tier Model

```
┌─────────────────────────────────────────┐
│ DMZ Zone (Public-facing)                │
│ - NAT Gateways                          │
│ - Internet Gateways                     │
│ - Load balancers                        │
│ - Bastion/Jump hosts (optional)         │
└─────────────────────────────────────────┘
           ↓
┌─────────────────────────────────────────┐
│ App Zone (Application tier)             │
│ - Web servers                           │
│ - Application servers                   │
│ - Container workloads                   │
└─────────────────────────────────────────┘
           ↓
┌─────────────────────────────────────────┐
│ Data Zone (Database tier)               │
│ - RDS/Azure SQL                         │
│ - NoSQL databases                       │
│ - Data warehouses                       │
└─────────────────────────────────────────┘
           ↑
┌─────────────────────────────────────────┐
│ Management Zone (Admin/Ops)             │
│ - Monitoring tools                      │
│ - Logging infrastructure                │
│ - CI/CD agents                          │
└─────────────────────────────────────────┘
```

### Security Zones by Trust Level

| Zone | Trust Level | Internet Access | Cross-Zone Access |
|------|-------------|-----------------|-------------------|
| DMZ | Low | Direct (IGW) | → App only |
| App | Medium | Via NAT | → Data, ↔ Mgmt |
| Data | High | Via NAT (restrictive) | ← App only |
| Management | Medium-High | Via NAT | → All zones |

### Subnet Sizing Rationale

**Web/App Subnets: /22 (1,019 IPs)**
- Supports auto-scaling (100-500 instances)
- Room for containers (ENI per pod/task)
- EKS: 1 node needs 10-20 IPs for pods

**Data Subnets: /23 (507 IPs)**
- Fewer database instances
- RDS Multi-AZ uses 2-3 IPs
- Read replicas need additional IPs

**Management: /24 (251 IPs)**
- Bastion, monitoring, logging
- Less elastic scaling needed

**Transit/Gateway: /28 (11 IPs)**
- Transit Gateway needs 1 IP per AZ
- Minimal footprint

## Routing Architecture

### AWS Routing Design

#### Hub VPC Route Tables

**Public Subnet Route Table (DMZ)**

| Destination | Target | Purpose |
|-------------|--------|---------|
| 10.0.0.0/16 | local | Intra-VPC |
| 10.1.0.0/16 | TGW | → Spoke 1 |
| 10.2.0.0/16 | TGW | → Spoke 2 |
| 10.3.0.0/16 | TGW | → Spoke 3 |
| 10.100.0.0/12 | VPN | → Azure via VPN |
| 0.0.0.0/0 | IGW | Internet |

**Private Subnet Route Table (Shared Services)**

| Destination | Target | Purpose |
|-------------|--------|---------|
| 10.0.0.0/16 | local | Intra-VPC |
| 10.1.0.0/16 | TGW | → Spoke 1 |
| 10.2.0.0/16 | TGW | → Spoke 2 |
| 10.3.0.0/16 | TGW | → Spoke 3 |
| 10.100.0.0/12 | VPN | → Azure via VPN |
| 0.0.0.0/0 | NAT-GW | Internet via NAT |

#### Spoke VPC Route Tables

**All Private Subnets (App, Data)**

| Destination | Target | Purpose |
|-------------|--------|---------|
| 10.X.0.0/16 | local | Intra-VPC |
| 10.0.0.0/16 | TGW | → Hub |
| 10.1.0.0/16 | TGW | → Other spoke (direct) |
| 10.2.0.0/16 | TGW | → Other spoke (direct) |
| 10.3.0.0/16 | TGW | → Other spoke (direct) |
| 10.100.0.0/12 | TGW | → Azure (via hub VPN) |
| 0.0.0.0/0 | TGW | Internet via Hub NAT |

#### Transit Gateway Route Tables

**TGW Route Table: Direct Spoke Routing**

| Destination | Attachment | Purpose |
|-------------|------------|---------|
| 10.0.0.0/16 | Hub VPC | To hub |
| 10.1.0.0/16 | Spoke 1 VPC | Direct spoke access |
| 10.2.0.0/16 | Spoke 2 VPC | Direct spoke access |
| 10.3.0.0/16 | Spoke 3 VPC | Direct spoke access |
| 10.100.0.0/12 | Hub VPC (VPN) | To Azure via hub VPN |
| 0.0.0.0/0 | Hub VPC | Default to hub NAT |

**Configuration**: Single route table with all spoke attachments associated (enables direct spoke-to-spoke communication)

### Azure Routing Design

#### Hub VNet Route Table (User Defined Routes)

**Applied to: Shared services subnet**

| Address Prefix | Next Hop | Purpose |
|----------------|----------|---------|
| 10.100.0.0/16 | VNet | Local routing |
| 10.101.0.0/16 | VNet Peering | → Spoke 1 |
| 10.102.0.0/16 | VNet Peering | → Spoke 2 |
| 10.103.0.0/16 | VNet Peering | → Spoke 3 |
| 10.0.0.0/12 | VPN Gateway | → AWS via VPN |
| 0.0.0.0/0 | Azure Firewall | Centralized egress |

#### Spoke VNet Route Tables

**Applied to: All spoke subnets**

| Address Prefix | Next Hop | Purpose |
|----------------|----------|---------|
| 10.10X.0.0/16 | VNet | Local routing |
| 10.100.0.0/16 | VNet Peering | → Hub |
| 10.101.0.0/16 | VNet Peering | → Other spoke (direct) |
| 10.102.0.0/16 | VNet Peering | → Other spoke (direct) |
| 10.103.0.0/16 | VNet Peering | → Other spoke (direct) |
| 10.0.0.0/12 | VNet Peering → VPN | → AWS via hub VPN |
| 0.0.0.0/0 | VNet Peering → Firewall | Internet via hub |

**VNet Peering Configuration**:
- ✅ Allow forwarded traffic (enables spoke-to-spoke)
- ✅ Use remote gateway (spokes use hub VPN gateway)
- ✅ Allow gateway transit (on hub peering only)

## NAT Gateway Strategy

### AWS NAT Gateway Design

**Placement**: One NAT Gateway per AZ in Hub VPC DMZ subnets
- **hub-dmz-public-1a** → NAT Gateway A (10.0.0.0/24)
- **hub-dmz-public-1b** → NAT Gateway B (10.0.1.0/24)

**Traffic Flow**: Spoke → TGW → Hub Private Subnet → NAT Gateway → IGW → Internet

**High Availability**:
- 2 NAT Gateways (one per AZ) for redundancy
- Each spoke can fail over between AZs
- Single point of egress monitoring and control

**Cost Optimization**:
- Centralized NAT reduces per-VPC NAT costs
- Development environments share production NAT
- Cost: ~$0.045/hour/NAT + $0.045/GB processed
- Estimated monthly: ~$70 (2 NAT GW) + data transfer

**Alternative Pattern** (documented but not implemented):
- Per-spoke NAT for data-heavy workloads
- Trade cost for reduced inter-VPC data transfer charges

### Azure NAT Gateway Design

**Placement**: Hub-based NAT via Azure Firewall
- Azure Firewall provides SNAT (Source NAT) functionality
- All spoke traffic routes through firewall for egress

**Alternative Option** (lower cost):
- Deploy Azure NAT Gateway in hub
- Associate with specific spoke subnets requiring high throughput
- Cheaper than Firewall SNAT for high-volume scenarios

**Decision Matrix**:

| Scenario | AWS Solution | Azure Solution |
|----------|--------------|----------------|
| Cost-optimized | Hub NAT (centralized) | Hub Firewall SNAT |
| High throughput | Hub NAT (still cost-effective) | Azure NAT Gateway |
| Security-focused | Hub NAT + inspection | Azure Firewall SNAT |
| Development | Hub NAT (shared) | Firewall SNAT (shared) |

## VPN/IPsec Connectivity Architecture

### Design Decision: Hub-to-Hub VPN with Merged Routing Domains

**Topology**: AWS Hub VPC ↔ IPsec VPN ↔ Azure Hub VNet

**Key Principle**: VPN merges routing domains, allowing all AWS subnets to reach all Azure subnets and vice versa.

### AWS Side Configuration

#### VPN Gateway Setup

**Component**: AWS Virtual Private Gateway (VGW) attached to Hub VPC

| Parameter | Value |
|-----------|-------|
| Type | RouteBased VPN |
| ASN | 64512 (AWS side) |
| Attachment | aws-hub-vpc (10.0.0.0/16) |
| Redundancy | 2 tunnels (active/standby) |

#### Customer Gateway (Azure side endpoint)

| Parameter | Value |
|-----------|-------|
| IP Address | Azure VPN Gateway Public IP |
| BGP ASN | 65515 (Azure default) |
| Routing | BGP (dynamic) |

#### VPN Connection

| Parameter | Value |
|-----------|-------|
| Tunnel 1 CIDR | 169.254.21.0/30 (AWS assigns) |
| Tunnel 2 CIDR | 169.254.22.0/30 (AWS assigns) |
| Pre-shared Key | Generated (store in AWS Secrets Manager) |
| IKE Version | IKEv2 |
| Encryption | AES256 |
| DH Group | Group 14 (2048-bit) |
| PFS | Enabled |

### Azure Side Configuration

#### VPN Gateway Setup

**Component**: Azure VPN Gateway in Hub VNet

| Parameter | Value |
|-----------|-------|
| Type | VPN (Route-based) |
| SKU | VpnGw2 (1.25 Gbps) |
| Subnet | GatewaySubnet (10.100.2.0/27) |
| Active-Active | Yes (2 instances for HA) |
| BGP | Enabled (ASN 65515) |

#### Local Network Gateway (AWS side endpoint)

| Parameter | Value |
|-----------|-------|
| Name | lng-aws-hub |
| IP Address | AWS VGW Public IP Tunnel 1 |
| Address Space | 10.0.0.0/12 (entire AWS range) |
| BGP Peer IP | 169.254.21.1 |

#### Connection

| Parameter | Value |
|-----------|-------|
| Connection Type | IPsec |
| Shared Key | Match AWS Pre-shared Key |
| IKE Protocol | IKEv2 |
| IPsec/IKE Policy | Custom (match AWS) |
| Use Policy-Based TS | No (route-based) |

### Routing Propagation

#### AWS Transit Gateway Route Table Updates

**Add these routes** (learned via VPN + BGP):

| Destination | Next Hop | Learned From |
|-------------|----------|--------------|
| 10.100.0.0/16 | VPN Connection | BGP from Azure |
| 10.101.0.0/16 | VPN Connection | BGP from Azure |
| 10.102.0.0/16 | VPN Connection | BGP from Azure |
| 10.103.0.0/16 | VPN Connection | BGP from Azure |

**TGW Route Propagation**:
- Enable automatic route propagation to spoke VPCs via TGW
- All spokes automatically learn Azure routes
- Spokes send Azure-destined traffic to TGW → Hub VPN

#### Azure VNet Peering Route Tables

**Hub VNet UDR** (applied to GatewaySubnet):

| Address Prefix | Next Hop | Purpose |
|----------------|----------|---------|
| 10.0.0.0/12 | Virtual Network Gateway | To AWS via VPN |
| 10.100.0.0/12 | VNet | Local Azure VNets |

**Spoke VNet UDRs** (add AWS routes):

| Address Prefix | Next Hop | Purpose |
|----------------|----------|---------|
| 10.0.0.0/12 | VNet Peering → Hub → VPN | To AWS |

**Enable**:
- ✅ "Use Remote Gateway" on spoke peerings
- ✅ "Allow Gateway Transit" on hub peerings
- ✅ "Allow Forwarded Traffic" for spoke-to-spoke via hub

### Traffic Flow Examples

#### Example 1: AWS Spoke 1 → Azure Spoke 1

```
Source: 10.1.10.5 (aws-spoke-prod-vpc, app tier)
Destination: 10.101.10.5 (azure-spoke-prod-vnet, app tier)

Flow:
1. aws-spoke-prod subnet route table: 10.101.0.0/16 → TGW
2. TGW route table: 10.101.0.0/16 → aws-hub-vpc attachment
3. Hub VPC routes to VPN Gateway
4. AWS VPN Gateway → IPsec Tunnel → Azure VPN Gateway
5. Azure Hub UDR: 10.101.0.0/16 → VNet Peering (spoke-prod)
6. Packet reaches 10.101.10.5
```

#### Example 2: Azure App → AWS GuardDuty (security spoke)

```
Source: 10.101.10.5 (azure-spoke-prod-vnet, app)
Destination: 10.3.20.10 (aws-spoke-security-vpc, GuardDuty collector)

Flow:
1. azure-spoke-prod UDR: 10.0.0.0/12 → VNet Peering (hub)
2. Azure Hub GatewaySubnet UDR: 10.3.0.0/16 → VPN Gateway
3. Azure VPN Gateway → IPsec Tunnel → AWS VPN Gateway
4. AWS TGW route table: 10.3.0.0/16 → spoke-security-vpc attachment
5. Packet reaches 10.3.20.10
```

#### Example 3: AWS Spoke 1 → AWS Spoke 2 (Direct Spoke Routing)

```
Source: 10.1.10.5 (aws-spoke-prod-vpc)
Destination: 10.2.10.5 (aws-spoke-dev-vpc)

Flow:
1. aws-spoke-prod route table: 10.2.0.0/16 → TGW
2. TGW route table: 10.2.0.0/16 → spoke-dev-vpc attachment
3. Packet reaches 10.2.10.5 directly (no hub traversal)
```

### High Availability Design

**AWS Side**:
- 2 VPN tunnels (AWS standard, different AZ endpoints)
- BGP session on both tunnels (active/standby)
- Failover time: 30-60 seconds (BGP convergence)

**Azure Side**:
- Active-Active VPN Gateway (2 instances)
- 2 IPsec connections (one to each AWS tunnel endpoint)
- Zone-redundant gateway for maximum availability

**Failure Scenarios**:
- Single tunnel failure: BGP routes withdrawn, traffic shifts to standby
- Gateway failure: Azure active-active promotes secondary instance
- Network partition: BGP hold timer (default 180s) triggers failover

### Monitoring & Validation

#### AWS Metrics

```bash
# Check VPN tunnel status
aws ec2 describe-vpn-connections --vpn-connection-ids vpn-xxxxx \
  --query 'VpnConnections[0].VgwTelemetry'

# CloudWatch metrics to monitor
- TunnelState (UP/DOWN)
- TunnelDataIn/TunnelDataOut (bytes)
```

**CloudWatch Alarms**:
- Alert when both tunnels DOWN
- Alert on tunnel flapping (multiple state changes)

#### Azure Metrics

```bash
# Check VPN gateway status
az network vpn-connection show \
  --name conn-to-aws \
  --resource-group rg-network-hub \
  --query 'connectionStatus'

# Metrics to monitor
- Gateway S2S Bandwidth
- Tunnel Ingress/Egress Bytes
- Tunnel Ingress/Egress Packet Drop Count
```

### Cost Estimation

| Component | AWS Cost | Azure Cost |
|-----------|----------|------------|
| VPN Gateway | $0.05/hour (~$36/mo) | VpnGw2: $0.54/hour (~$390/mo) |
| Data Transfer | $0.09/GB out | $0.087/GB out |
| **Monthly (100GB)** | **~$45** | **~$399** |
| **Monthly (1TB)** | **~$126** | **~$477** |

**Note**: Azure VPN Gateway significantly more expensive than AWS. For production high-throughput scenarios, consider ExpressRoute/Direct Connect.

## Firewall Rule Taxonomy

### Naming Convention

**Format**: `{direction}_{zone}_{protocol}_{source}_{destination}_{action}_{priority}`

**Examples**:
- `inbound_dmz_https_internet_alb_allow_100`
- `outbound_app_https_app_internet_allow_200`
- `internal_data_postgres_app_db_allow_300`

### Rule Categories

#### 1. Internet Ingress Rules (DMZ Zone)

| Rule Name | Source | Destination | Protocol | Port | Action |
|-----------|--------|-------------|----------|------|--------|
| `inbound_dmz_https_internet_alb_allow_100` | 0.0.0.0/0 | ALB (DMZ) | TCP | 443 | Allow |
| `inbound_dmz_http_internet_alb_allow_101` | 0.0.0.0/0 | ALB (DMZ) | TCP | 80 | Allow (redirect) |
| `inbound_dmz_ssh_admin_bastion_allow_150` | Admin IPs | Bastion | TCP | 22 | Allow |
| `inbound_dmz_rdp_admin_bastion_allow_151` | Admin IPs | Bastion | TCP | 3389 | Allow |
| `inbound_dmz_deny_all_900` | Any | Any | Any | Any | Deny |

#### 2. Internet Egress Rules (NAT Gateway)

| Rule Name | Source | Destination | Protocol | Port | Action |
|-----------|--------|-------------|----------|------|--------|
| `outbound_app_https_app_internet_allow_200` | App Subnets | 0.0.0.0/0 | TCP | 443 | Allow |
| `outbound_app_http_app_internet_allow_201` | App Subnets | 0.0.0.0/0 | TCP | 80 | Allow |
| `outbound_app_dns_app_internet_allow_202` | App Subnets | 0.0.0.0/0 | UDP | 53 | Allow |
| `outbound_app_ntp_app_internet_allow_203` | App Subnets | 0.0.0.0/0 | UDP | 123 | Allow |
| `outbound_data_deny_internet_data_internet_deny_800` | Data Subnets | 0.0.0.0/0 | Any | Any | Deny |

#### 3. Internal Cross-Zone Rules

| Rule Name | Source | Destination | Protocol | Port | Action |
|-----------|--------|-------------|----------|------|--------|
| `internal_app_http_dmz_app_allow_300` | DMZ | App Subnets | TCP | 8080 | Allow |
| `internal_app_https_dmz_app_allow_301` | DMZ | App Subnets | TCP | 8443 | Allow |
| `internal_data_postgres_app_db_allow_400` | App Subnets | Data Subnets | TCP | 5432 | Allow |
| `internal_data_mysql_app_db_allow_401` | App Subnets | Data Subnets | TCP | 3306 | Allow |
| `internal_data_redis_app_cache_allow_402` | App Subnets | Data Subnets | TCP | 6379 | Allow |
| `internal_data_mongodb_app_nosql_allow_403` | App Subnets | Data Subnets | TCP | 27017 | Allow |

#### 4. Management Zone Rules

| Rule Name | Source | Destination | Protocol | Port | Action |
|-----------|--------|-------------|----------|------|--------|
| `mgmt_ssh_mgmt_all_allow_500` | Mgmt Subnets | All Private | TCP | 22 | Allow |
| `mgmt_rdp_mgmt_all_allow_501` | Mgmt Subnets | All Private | TCP | 3389 | Allow |
| `mgmt_https_all_monitoring_allow_510` | All Subnets | Mgmt (Monitoring) | TCP | 443 | Allow |
| `mgmt_syslog_all_logging_allow_511` | All Subnets | Mgmt (Logging) | UDP | 514 | Allow |

#### 5. Cross-Cloud Rules (VPN Traffic)

| Rule Name | Source | Destination | Protocol | Port | Action |
|-----------|--------|-------------|----------|------|--------|
| `vpn_all_aws_azure_allow_600` | 10.0.0.0/12 | 10.100.0.0/12 | Any | Any | Allow |
| `vpn_all_azure_aws_allow_601` | 10.100.0.0/12 | 10.0.0.0/12 | Any | Any | Allow |

**Note**: Initially allow all cross-cloud traffic, then tighten based on actual application needs.

### Rule Priority Guidelines

| Priority Range | Purpose |
|----------------|---------|
| 100-199 | Critical inbound (public-facing) |
| 200-299 | Internet egress |
| 300-399 | DMZ ↔ App tier |
| 400-499 | App ↔ Data tier |
| 500-599 | Management access |
| 600-699 | Cross-cloud VPN |
| 700-799 | Monitoring & logging |
| 800-899 | Explicit denies |
| 900-999 | Default deny-all |

### AWS Security Group Implementation

**Security Group**: `sg-dmz-alb`

```hcl
resource "aws_security_group" "dmz_alb" {
  name        = "sg-dmz-alb"
  description = "Security group for DMZ Application Load Balancer"
  vpc_id      = aws_vpc.hub.id

  ingress {
    description = "inbound_dmz_https_internet_alb_allow_100"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    description = "inbound_dmz_http_internet_alb_allow_101"
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    description = "outbound_app_http_dmz_app_allow_300"
    from_port   = 8080
    to_port     = 8080
    protocol    = "tcp"
    cidr_blocks = ["10.0.0.0/12", "10.100.0.0/12"]
  }

  tags = {
    Name = "sg-dmz-alb"
  }
}
```

### Azure NSG Implementation

**Network Security Group**: `nsg-dmz`

```hcl
resource "azurerm_network_security_group" "dmz" {
  name                = "nsg-dmz"
  location            = azurerm_resource_group.network.location
  resource_group_name = azurerm_resource_group.network.name

  security_rule {
    name                       = "inbound_dmz_https_internet_alb_allow_100"
    priority                   = 100
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "Tcp"
    source_port_range          = "*"
    destination_port_range     = "443"
    source_address_prefix      = "Internet"
    destination_address_prefix = "10.100.10.0/24"
  }

  security_rule {
    name                       = "inbound_dmz_http_internet_alb_allow_101"
    priority                   = 101
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "Tcp"
    source_port_range          = "*"
    destination_port_range     = "80"
    source_address_prefix      = "Internet"
    destination_address_prefix = "10.100.10.0/24"
  }

  tags = {
    Name = "nsg-dmz"
  }
}
```

### Security Group Strategy

**AWS Pattern**: Stateful, per-resource
- One SG per tier (web-sg, app-sg, db-sg)
- Reference other SGs as sources (not CIDRs)
- Example: `db-sg` allows `app-sg` as source

```hcl
# Database SG allows app SG as source
resource "aws_security_group" "database" {
  ingress {
    description     = "internal_data_postgres_app_db_allow_400"
    from_port       = 5432
    to_port         = 5432
    protocol        = "tcp"
    security_groups = [aws_security_group.app.id]
  }
}
```

**Azure Pattern**: NSG per subnet
- Applied at subnet level
- Service tags for Azure services
- Example: `Allow AzureLoadBalancer` using service tag

```hcl
security_rule {
  name                       = "allow_azure_lb"
  source_address_prefix      = "AzureLoadBalancer"
  destination_address_prefix = "*"
  access                     = "Allow"
}
```

## IPAM Strategy (IP Address Management)

### Allocation Hierarchy

```
10.0.0.0/8 (Overall Private Space)
├── 10.0.0.0/12   → AWS (16 VPCs possible)
│   ├── 10.0.0.0/16  → aws-hub-vpc
│   ├── 10.1.0.0/16  → aws-spoke-prod-vpc
│   ├── 10.2.0.0/16  → aws-spoke-dev-vpc
│   ├── 10.3.0.0/16  → aws-spoke-security-vpc
│   └── 10.4-15.0.0/16 → Reserved for future AWS VPCs
│
├── 10.100.0.0/12 → Azure (16 VNets possible)
│   ├── 10.100.0.0/16 → azure-hub-vnet
│   ├── 10.101.0.0/16 → azure-spoke-prod-vnet
│   ├── 10.102.0.0/16 → azure-spoke-dev-vnet
│   ├── 10.103.0.0/16 → azure-spoke-security-vnet
│   └── 10.104-111.0.0/16 → Reserved for future Azure VNets
│
├── 10.200.0.0/12 → Reserved for GCP
└── 10.220.0.0/12 → Reserved for On-Premises
```

### Reservation Process

#### New VPC/VNet Request Template

**File**: `.github/ISSUE_TEMPLATE/network-request.md`

```yaml
---
Name: Network Allocation Request
Labels: network, ipam
---

## Network Details
- **Cloud Provider**: [AWS/Azure/GCP]
- **Environment**: [prod/dev/staging/security]
- **Purpose**: [Brief description]
- **Expected Resource Count**: [Number of instances/VMs]

## Sizing Requirements
- **Compute Instances**: ~___
- **Databases**: ~___
- **Load Balancers**: ~___
- **Expected Growth**: ___% over 12 months

## Requested CIDR
- **Preferred**: 10.__.0.0/16
- **Justification**: [Why this range?]

## Approvals
- [ ] Reviewed IPAM spreadsheet for conflicts
- [ ] No overlap with existing allocations
- [ ] Approved by: @network-admin
```

### Subnet Naming Convention

**Pattern**: `{cloud}-{vpc-name}-{tier}-{az}`

**Examples**:
- `aws-hub-dmz-public-1a`
- `aws-spoke-prod-app-private-1b`
- `azure-hub-firewall` (Azure reserved names)
- `azure-spoke-prod-web`

### Validation Checklist (Pre-Deployment)

Before deploying any new VPC/VNet:

```bash
# Check for CIDR overlaps
# Run this script: /scripts/validate-cidr.sh

#!/bin/bash
NEW_CIDR="10.4.0.0/16"

echo "Checking for overlaps with: $NEW_CIDR"

# AWS VPCs
echo "=== AWS VPCs ==="
aws ec2 describe-vpcs --query 'Vpcs[*].CidrBlock' --output text

# Azure VNets
echo "=== Azure VNets ==="
az network vnet list --query '[*].addressSpace.addressPrefixes[]' -o tsv

echo ""
echo "Manual check: Does $NEW_CIDR overlap with any above?"
```

**Validation Steps**:
- [ ] No overlap with existing AWS VPCs
- [ ] No overlap with existing Azure VNets
- [ ] No overlap with reserved ranges (GCP, on-prem)
- [ ] CIDR is within allocated cloud range (10.0.0.0/12 or 10.100.0.0/12)
- [ ] Documented in IPAM spreadsheet
- [ ] GitHub issue created and approved

### Growth Planning

#### Current Utilization

| Cloud | Allocated | Used | Available | Utilization |
|-------|-----------|------|-----------|-------------|
| AWS | 10.0.0.0/12 | 4 × /16 | 12 × /16 | 25% |
| Azure | 10.100.0.0/12 | 4 × /16 | 12 × /16 | 25% |

#### Projected Growth (12 months)

| Environment | Current VPCs/VNets | Projected | New Ranges Needed |
|-------------|-------------------|-----------|-------------------|
| Production | 2 (1 AWS + 1 Azure) | 4 | 2 × /16 |
| Development | 2 (1 AWS + 1 Azure) | 3 | 1 × /16 |
| Security | 2 (1 AWS + 1 Azure) | 2 | 0 |
| **Total** | **6** | **9** | **3 × /16** |

**Runway**: 12 × /16 available per cloud = **3-4 years at current growth rate**

### Tools & Automation

**Recommended Tools**:
- **Manual Tracking**: Google Sheets / Excel with IPAM registry
- **CI/CD Validation**: Terraform `cidrsubnet()` and `cidrhost()` functions
- **Overlap Detection**: Python `ipaddress` module in pre-commit hook
- **Enterprise (Future)**: AWS IPAM service, Azure IPAM solution

**Terraform Automation Example**:

```hcl
locals {
  aws_base_cidr = "10.0.0.0/12"

  # Calculate spoke CIDRs automatically
  spoke_cidrs = {
    hub      = cidrsubnet(local.aws_base_cidr, 4, 0)  # 10.0.0.0/16
    prod     = cidrsubnet(local.aws_base_cidr, 4, 1)  # 10.1.0.0/16
    dev      = cidrsubnet(local.aws_base_cidr, 4, 2)  # 10.2.0.0/16
    security = cidrsubnet(local.aws_base_cidr, 4, 3)  # 10.3.0.0/16
  }
}

# Subnet calculation within VPC
locals {
  prod_vpc_cidr = local.spoke_cidrs.prod  # 10.1.0.0/16

  prod_subnets = {
    web_1a  = cidrsubnet(local.prod_vpc_cidr, 6, 0)   # 10.1.0.0/22
    web_1b  = cidrsubnet(local.prod_vpc_cidr, 6, 1)   # 10.1.4.0/22
    app_1a  = cidrsubnet(local.prod_vpc_cidr, 6, 2)   # 10.1.8.0/22 (adjusted to 10.1.10.0/22)
    app_1b  = cidrsubnet(local.prod_vpc_cidr, 6, 3)   # 10.1.12.0/22 (adjusted to 10.1.14.0/22)
    data_1a = cidrsubnet(local.prod_vpc_cidr, 7, 10)  # 10.1.20.0/23
    data_1b = cidrsubnet(local.prod_vpc_cidr, 7, 11)  # 10.1.22.0/23
  }
}
```

## References

- [AWS VPC Design Best Practices](https://docs.aws.amazon.com/vpc/latest/userguide/vpc-design-best-practices.html)
- [Azure Hub-Spoke Topology](https://docs.microsoft.com/en-us/azure/architecture/reference-architectures/hybrid-networking/hub-spoke)
- [AWS Transit Gateway Documentation](https://docs.aws.amazon.com/vpc/latest/tgw/)
- [CIDR Allocation: docs/architecture/cidr-allocation.md](./cidr-allocation.md)
- [IPAM Registry: docs/architecture/ipam-registry.csv](./ipam-registry.csv)
- [Topology Diagrams: diag/](../../diag/)
