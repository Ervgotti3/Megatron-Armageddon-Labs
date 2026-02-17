Megatron Armageddon Labs

Secure AWS Application Architecture – From Foundational Pattern to Edge-Hardened Production Design

Overview

This project documents the design and implementation of a secure, production-style AWS architecture using Terraform.

It begins with a foundational EC2 → RDS pattern (Lab 1) and evolves into a hardened, edge-protected architecture using CloudFront origin cloaking and WAF enforcement (Lab 2).

The objective was not to build a complex application — it was to build secure infrastructure patterns that mirror real enterprise workloads.

Lab 1 – EC2 → RDS Foundational Pattern
Objective

Build and validate a classic cloud application architecture:

EC2 (compute layer)

RDS MySQL (managed database)

Secrets Manager (credential management)

IAM roles (no static credentials)

Security groups enforcing least privilege

VPC-based network isolation

This pattern is foundational to:

Internal enterprise tools

SaaS backends

Lift-and-shift migrations

DevOps and SRE environments

Security assessments

AWS Solutions Architect interviews

If you understand this pattern, you understand the backbone of most AWS workloads.

Architecture – Lab 1
User → EC2 → RDS
              ↑
       Secrets Manager

Logical Flow

User sends HTTP request to EC2 instance

EC2 application:

Assumes IAM role

Retrieves DB credentials from Secrets Manager

Connects to RDS endpoint

Application writes/reads data

Response returned to user

Security Model – Lab 1

RDS is not publicly accessible

RDS only allows inbound traffic from EC2 Security Group

EC2 uses IAM role to retrieve secrets

No passwords stored in:

source code

AMIs

environment variables

Least privilege security group design

TLS termination at ALB

This design enforces real-world trust boundaries.

Terraform Concepts Implemented (Lab 1)

Modular resource design

Dynamic naming with random_id

Secrets stored in AWS Secrets Manager

IAM role + instance profile for EC2

Private RDS subnet placement

ALB with HTTPS listener

DNS via Route53

S3 bucket for ALB access logs

CloudWatch logging and metrics

Lab 1 Verification

Confirm EC2 can retrieve DB credentials

Confirm EC2 can connect to RDS

Confirm RDS is not publicly reachable

Confirm ALB is serving application traffic

Confirm Secrets Manager contains credentials

Confirm security groups enforce least privilege

Lab 2 – Edge Security & Origin Cloaking
Objective

Transform the Lab 1 architecture into a production-grade edge-hardened design.

Key Requirements

Only CloudFront is publicly reachable

ALB is cloaked and cannot be accessed directly

WAF enforcement moves from ALB → CloudFront

DNS points to CloudFront, not ALB

Defense-in-depth origin protection

Architecture – Lab 2
Internet
   ↓
CloudFront (WAF at Edge)
   ↓
ALB (Origin Cloaked)
   ↓
Private EC2
   ↓

Security Enhancements Introduced in Lab 2
1. Origin Cloaking

The ALB is technically internet-facing, but functionally private.

Controls implemented:

Security Group allows inbound only from:
AWS-managed prefix list
com.amazonaws.global.cloudfront.origin-facing

ALB listener rule requires a secret custom header:
X-Megatron-Growl

Requests missing the header receive HTTP 403

Even if someone knows the ALB DNS name, they cannot bypass CloudFront.   

2. WAF Enforcement at the Edge

WAFv2 scope = "CLOUDFRONT"

AWS Managed Rules enabled

Associated directly to CloudFront distribution

All filtering happens before traffic reaches origin

3. DNS Migration

Route53 updated:

technology4gold.com → CloudFront

app.technology4gold.com → CloudFront

Verified via:

aws route53 list-resource-record-sets ...

Lab 2 Verification Results
Alias target confirms CloudFront domain.

Direct ALB Access
curl -k -I https://<ALB_DNS>


Result: 403 Forbidden

CloudFront Access
curl -I https://technology4gold.com
curl -I https://app.technology4gold.com


Result: 200 OK

✔ CloudFront is sole ingress

WAF Attached
aws cloudfront get-distribution ...


Result: WebACL ARN present

✔ Edge enforcement confirmed

Terraform Concepts Demonstrated (Lab 2)

Multiple provider configuration (us-east-1 for CloudFront ACM)

Terraform-managed ACM certificate validation

Random secret generation for origin header

AWS-managed prefix lists

WAFv2 global scope configuration

Conditional resource indexing with count

DNS UPSERT with allow_overwrite = true

Dependency management across regions

What This Project Demonstrates

This is not a toy lab.

It demonstrates the ability to:

Design secure AWS network boundaries

Implement least privilege correctly

Move security controls to the edge

Prevent origin bypass

Manage multi-region infrastructure with Terraform

Debug real-world issues (DNS conflicts, validation records, resource dependencies)

Validate infrastructure through CLI testing

Skills Demonstrated

AWS VPC architecture

EC2 / RDS integration

Secrets Manager usage

IAM roles and trust policies

ALB listener rules

CloudFront custom origin configuration

WAFv2 configuration (regional + global)

Route53 DNS management

Infrastructure-as-Code with Terraform

Incident-style debugging and verification

*** Future Enhancements ***

Remote Terraform state (S3 + DynamoDB locking)

Terraform modules separation

CI/CD pipeline integration

OIDC authentication for GitHub Actions

PrivateLink or internal ALB architecture

CloudFront cache policy optimization