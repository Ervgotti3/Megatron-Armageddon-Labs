# Megatron Armageddon Labs 1–3

![AWS](https://img.shields.io/badge/AWS-Cloud-232F3E?style=for-the-badge&logo=amazonaws&logoColor=white)
![Terraform](https://img.shields.io/badge/Terraform-IaC-623CE4?style=for-the-badge&logo=terraform&logoColor=white)
![CloudFront](https://img.shields.io/badge/CloudFront-Edge-orange?style=for-the-badge)
![WAF](https://img.shields.io/badge/WAF-Enabled-success?style=for-the-badge)
![Security](https://img.shields.io/badge/Security-Defense--in--Depth-blue?style=for-the-badge)

## Secure AWS Application Architecture
### From Foundational Pattern to Edge-Hardened Production Design

> [!IMPORTANT]
> This project documents a secure, production-style AWS architecture built with Terraform. It starts with a foundational EC2 → RDS pattern and evolves into an edge-hardened design using CloudFront origin cloaking and WAF enforcement.

## Table of Contents

- [Overview](#overview)
- [Project Highlights](#project-highlights)
- [Architecture Progression](#architecture-progression)
- [Lab 1 – EC2 → RDS Foundational Pattern](#lab-1--ec2--rds-foundational-pattern)
- [Lab 2 – Edge Security & Origin Cloaking](#lab-2--edge-security--origin-cloaking)
- [What This Project Demonstrates](#what-this-project-demonstrates)
- [Skills Demonstrated](#skills-demonstrated)
- [Future Enhancements](#future-enhancements)

## Overview

This project documents the design and implementation of a secure, production-style AWS architecture using Terraform.

It begins with a foundational EC2 → RDS pattern and evolves into a hardened, edge-protected architecture using CloudFront origin cloaking and WAF enforcement.

The goal was not to build a complex application — it was to build secure infrastructure patterns that mirror real enterprise workloads.

## Project Highlights

- [x] EC2 application tier connected to private RDS
- [x] Secrets Manager used for credential management
- [x] IAM roles used instead of static credentials
- [x] Least-privilege security group design
- [x] ALB with HTTPS listener
- [x] CloudFront as sole public ingress
- [x] WAF enforcement at the edge
- [x] Origin cloaking with secret custom header
- [ ] Remote Terraform state with locking
- [ ] CI/CD pipeline integration
- [ ] OIDC authentication for GitHub Actions

## Architecture Progression

| Stage | Focus | Outcome |
|---|---|---|
| Lab 1 | EC2 → RDS foundational pattern | Secure application-to-database architecture with IAM, Secrets Manager, private networking, and ALB access |
| Lab 2 | CloudFront + WAF + origin cloaking | Edge protection, DNS migration to CloudFront, and defense-in-depth origin protection |
| Next | Production maturity improvements | Remote state, modules, CI/CD, OIDC, and cache policy optimization |

---

## Lab 1 – EC2 → RDS Foundational Pattern

### Objective

Build and validate a classic cloud application architecture using:

- EC2 as the compute layer
- RDS MySQL as the managed database
- Secrets Manager for credential management
- IAM roles for trusted access
- Security groups enforcing least privilege
- VPC-based network isolation

### Why This Pattern Matters

This pattern is foundational to:

- internal enterprise tools
- SaaS backends
- lift-and-shift migrations
- DevOps and SRE environments
- security assessments
- AWS Solutions Architect interviews

If you understand this pattern, you understand the backbone of many AWS workloads.

### Architecture – Lab 1

```text
User → EC2 → RDS
              ↑
       Secrets Manager
```

### Logical Flow

1. User sends an HTTP request to the EC2-hosted application.
2. The EC2 application assumes an IAM role.
3. The application retrieves database credentials from Secrets Manager.
4. The application connects to the RDS endpoint.
5. The application reads or writes data.
6. The response is returned to the user.

### Security Model – Lab 1

- RDS is not publicly accessible
- RDS only allows inbound traffic from the EC2 security group
- EC2 uses an IAM role to retrieve secrets
- No passwords are stored in source code, AMIs, or environment variables
- Least-privilege security group design is enforced
- TLS termination occurs at the ALB

This design enforces real-world trust boundaries.

### Terraform Concepts Implemented (Lab 1)

- modular resource design
- dynamic naming with `random_id`
- secrets stored in AWS Secrets Manager
- IAM role and instance profile for EC2
- private RDS subnet placement
- ALB with HTTPS listener
- DNS via Route53
- S3 bucket for ALB access logs
- CloudWatch logging and metrics

### Lab 1 Verification Checklist

- [x] EC2 can retrieve DB credentials
- [x] EC2 can connect to RDS
- [x] RDS is not publicly reachable
- [x] ALB is serving application traffic
- [x] Secrets Manager contains credentials
- [x] Security groups enforce least privilege

---

## Lab 2 – Edge Security & Origin Cloaking

### Objective

Transform the Lab 1 architecture into a production-grade, edge-hardened design.

### Key Requirements

- [x] Only CloudFront is publicly reachable
- [x] ALB is cloaked and cannot be accessed directly
- [x] WAF enforcement moves from ALB → CloudFront
- [x] DNS points to CloudFront instead of ALB
- [x] Defense-in-depth origin protection is enforced

### Architecture – Lab 2

```text
Internet
   ↓
CloudFront (WAF at Edge)
   ↓
ALB (Origin Cloaked)
   ↓
Private EC2
   ↓
RDS
```

### Security Enhancements Introduced in Lab 2

#### 1. Origin Cloaking

The ALB is technically internet-facing, but functionally private.

Controls implemented:

- security group allows inbound traffic only from the AWS-managed CloudFront origin-facing prefix list
- ALB listener rule requires a secret custom header: `X-Megatron-Growl`
- requests missing the header receive `403 Forbidden`

Even if someone knows the ALB DNS name, they cannot bypass CloudFront.

#### 2. WAF Enforcement at the Edge

- WAFv2 scope = `CLOUDFRONT`
- AWS Managed Rules enabled
- associated directly with the CloudFront distribution
- filtering happens before traffic reaches the origin

#### 3. DNS Migration

Route53 updated:

- `technology4gold.com` → CloudFront
- `app.technology4gold.com` → CloudFront

Verified via:

```bash
aws route53 list-resource-record-sets ...
```

### Lab 2 Verification Results

- [x] Alias target confirms CloudFront domain
- [x] Direct ALB access returns `403 Forbidden`
- [x] CloudFront access returns `200 OK`
- [x] CloudFront is the sole ingress path
- [x] WebACL ARN is present on the distribution
- [x] Edge enforcement confirmed

<details>
<summary><strong>Click to expand validation commands</strong></summary>

#### Direct ALB Access

```bash
curl -k -I https://<ALB_DNS>
```

**Result:** `403 Forbidden`

#### CloudFront Access

```bash
curl -I https://technology4gold.com
curl -I https://app.technology4gold.com
```

**Result:** `200 OK`

#### WAF Attached

```bash
aws cloudfront get-distribution ...
```

**Result:** `WebACL ARN present`

</details>

### Terraform Concepts Demonstrated (Lab 2)

- multiple provider configuration (`us-east-1` for CloudFront ACM)
- Terraform-managed ACM certificate validation
- random secret generation for origin header
- AWS-managed prefix lists
- WAFv2 global scope configuration
- conditional resource indexing with `count`
- DNS UPSERT with `allow_overwrite = true`
- dependency management across regions

---

## What This Project Demonstrates

This is not a toy lab.

It demonstrates the ability to:

- design secure AWS network boundaries
- implement least privilege correctly
- move security controls to the edge
- prevent origin bypass
- manage multi-region infrastructure with Terraform
- debug real-world issues such as DNS conflicts, validation records, and resource dependencies
- validate infrastructure through CLI testing

## Skills Demonstrated

- AWS VPC architecture
- EC2 / RDS integration
- Secrets Manager usage
- IAM roles and trust policies
- ALB listener rules
- CloudFront custom origin configuration
- WAFv2 configuration (regional + global)
- Route53 DNS management
- Infrastructure as Code with Terraform
- incident-style debugging and verification

## Future Enhancements

- [ ] Remote Terraform state (S3 + DynamoDB locking)
- [ ] Terraform module separation
- [ ] CI/CD pipeline integration
- [ ] OIDC authentication for GitHub Actions
- [ ] PrivateLink or internal ALB architecture
- [ ] CloudFront cache policy optimization

---

## Final Takeaway

This repository demonstrates how to evolve a foundational AWS application architecture into a more secure, edge-hardened production-style design using Terraform and AWS-native security controls.
