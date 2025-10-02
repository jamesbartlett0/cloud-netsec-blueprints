# CIDR Allocation Strategy

## Overview
Non-overlapping CIDR blocks for multi-cloud hub-spoke topology supporting production-grade network landing zones.

## Global Allocation Scheme

```
┌─────────────────────────────────────────────────────┐
│ Overall Allocation: 10.0.0.0/8                      │
│                                                      │
│ AWS:   10.0.0.0/12   (10.0-15.x.x)                 │
│ Azure: 10.100.0.0/12 (10.100-111.x.x)              │
│ Reserved: 10.200.0.0/12 (future GCP/on-prem)       │
└─────────────────────────────────────────────────────┘
```

## AWS Allocation (10.0.0.0/12)

| VPC Name | CIDR | Purpose | Max IPs | Region |
|----------|------|---------|---------|--------|
| aws-hub-vpc | 10.0.0.0/16 | Central hub, shared services | 65,536 | us-east-1 |
| aws-spoke-prod-vpc | 10.1.0.0/16 | Production workloads | 65,536 | us-east-1 |
| aws-spoke-dev-vpc | 10.2.0.0/16 | Development/test | 65,536 | us-east-1 |
| aws-spoke-security-vpc | 10.3.0.0/16 | Security tools, logging | 65,536 | us-east-1 |

### AWS Hub VPC (10.0.0.0/16) Subnet Breakdown

| Subnet Name | CIDR | AZ | Purpose | Available IPs |
|-------------|------|----|---------| -------------|
| hub-dmz-public-1a | 10.0.0.0/24 | us-east-1a | Public-facing (NAT, IGW) | 251 |
| hub-dmz-public-1b | 10.0.1.0/24 | us-east-1b | Public-facing (NAT, IGW) | 251 |
| hub-mgmt-private-1a | 10.0.10.0/24 | us-east-1a | Bastion, jump hosts | 251 |
| hub-mgmt-private-1b | 10.0.11.0/24 | us-east-1b | Bastion, jump hosts | 251 |
| hub-shared-svc-1a | 10.0.20.0/23 | us-east-1a | DNS, AD, monitoring | 507 |
| hub-shared-svc-1b | 10.0.22.0/23 | us-east-1b | DNS, AD, monitoring | 507 |
| hub-tgw-attach-1a | 10.0.30.0/28 | us-east-1a | Transit Gateway ENI | 11 |
| hub-tgw-attach-1b | 10.0.30.16/28 | us-east-1b | Transit Gateway ENI | 11 |

### AWS Spoke VPC Pattern (Applied to 10.1.0.0/16, 10.2.0.0/16, 10.3.0.0/16)

Replace X with 1, 2, or 3:

| Subnet Name | CIDR | AZ | Purpose | Available IPs |
|-------------|------|----|---------| -------------|
| spoke-web-1a | 10.X.0.0/22 | us-east-1a | Web tier | 1,019 |
| spoke-web-1b | 10.X.4.0/22 | us-east-1b | Web tier | 1,019 |
| spoke-app-1a | 10.X.10.0/22 | us-east-1a | Application tier | 1,019 |
| spoke-app-1b | 10.X.14.0/22 | us-east-1b | Application tier | 1,019 |
| spoke-data-1a | 10.X.20.0/23 | us-east-1a | Database tier | 507 |
| spoke-data-1b | 10.X.22.0/23 | us-east-1b | Database tier | 507 |
| spoke-tgw-attach-1a | 10.X.30.0/28 | us-east-1a | Transit Gateway | 11 |
| spoke-tgw-attach-1b | 10.X.30.16/28 | us-east-1b | Transit Gateway | 11 |

## Azure Allocation (10.100.0.0/12)

| VNet Name | CIDR | Purpose | Max IPs | Region |
|-----------|------|---------|---------|--------|
| azure-hub-vnet | 10.100.0.0/16 | Central hub | 65,536 | East US |
| azure-spoke-prod-vnet | 10.101.0.0/16 | Production | 65,536 | East US |
| azure-spoke-dev-vnet | 10.102.0.0/16 | Development | 65,536 | East US |
| azure-spoke-security-vnet | 10.103.0.0/16 | Security | 65,536 | East US |

### Azure Hub VNet (10.100.0.0/16) Subnet Breakdown

| Subnet Name | CIDR | Purpose | Available IPs |
|-------------|------|---------|---------------|
| AzureFirewallSubnet | 10.100.0.0/24 | Azure Firewall (reserved name) | 251 |
| AzureBastionSubnet | 10.100.1.0/26 | Azure Bastion (reserved name) | 59 |
| GatewaySubnet | 10.100.2.0/27 | VPN/ExpressRoute Gateway | 27 |
| hub-dmz | 10.100.10.0/24 | Public-facing services | 251 |
| hub-mgmt | 10.100.20.0/24 | Management services | 251 |
| hub-shared-svc | 10.100.30.0/23 | Shared services | 507 |

### Azure Spoke VNet Pattern (10.101-103.0.0/16)

Replace X with 101, 102, or 103:

| Subnet Name | CIDR | Purpose | Available IPs |
|-------------|------|---------|---------------|
| spoke-web | 10.X.0.0/22 | Web tier | 1,019 |
| spoke-app | 10.X.10.0/22 | Application tier | 1,019 |
| spoke-data | 10.X.20.0/23 | Database tier | 507 |
| spoke-integration | 10.X.30.0/24 | Integration services | 251 |

## Reserved Ranges

| CIDR | Purpose |
|------|---------|
| 10.200.0.0/12 | Future GCP deployment |
| 10.220.0.0/12 | Future on-premises connectivity |
| 10.240.0.0/12 | Future multi-region expansion |

## Validation Checklist

- [x] No overlap between AWS (10.0.0.0/12) and Azure (10.100.0.0/12)
- [x] Each spoke can support 100+ resources (1,019 IPs per app tier)
- [x] Subnet sizing follows /22 for compute, /23 for data
- [x] Reserved names used correctly (AzureFirewallSubnet, GatewaySubnet)
- [x] Room for expansion within each /16

## Subnet Calculator Reference

| CIDR | Subnet Mask | Total IPs | Usable IPs | Use Case |
|------|-------------|-----------|------------|----------|
| /16 | 255.255.0.0 | 65,536 | 65,531 | VPC/VNet |
| /22 | 255.255.252.0 | 1,024 | 1,019 | Web/App tier |
| /23 | 255.255.254.0 | 512 | 507 | Data tier |
| /24 | 255.255.255.0 | 256 | 251 | Management |
| /28 | 255.255.255.240 | 16 | 11 | TGW/Gateway |

**Note**: AWS and Azure both reserve 5 IPs per subnet (network, router/gateway, DNS, broadcast, future use)
