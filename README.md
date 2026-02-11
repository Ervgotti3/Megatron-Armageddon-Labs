# Megatron-Armageddon-Labs



LAB1



EC2 → RDS Integration Lab



Foundational Cloud Application Pattern



Project Overview (What You Are Building) In this lab, you will build a classic cloud application architecture: A compute layer running on an Amazon EC2 instance A managed relational database hosted on Amazon RDS Secure connectivity between the two using VPC networking and security groups Credential management using AWS Secrets Manager A simple application that writes and reads data from the database

The application itself is intentionally minimal. The learning value is not the app, but the cloud infrastructure pattern it demonstrates.



This pattern appears in: Internal enterprise tools SaaS products Backend APIs Legacy modernization projects Lift-and-shift workloads Cloud security assessments



If you can build and verify this pattern, you understand the foundation of real AWS workloads.



Why This Lab Exists (Industry Context) This Is One of the Most Common Interview Architectures Employers routinely expect engineers to understand: How EC2 communicates with RDS How database access is restricted Where credentials are stored How connectivity is validated How failures are debugged

You will encounter variations of this question in: AWS Solutions Architect interviews Cloud Security roles DevOps and SRE interviews Incident response scenarios



If you cannot explain this pattern clearly, you will struggle in real cloud environments.



Why This Pattern Matters to the Workforce What Employers Are Actually Testing This lab evaluates whether you understand:

Skill Why It Matters Security Groups Primary AWS network security boundary Least Privilege Prevents credential leakage \& lateral movement Managed Databases Operational responsibility vs infrastructure IAM Roles Eliminates static credentials Application-to-DB Trust Core of backend security



This is not a toy problem. This is how real systems are built.



Architectural Design (Conceptual) Logical Flow

A user sends an HTTP request to an EC2 instance

The EC2 application: Retrieves database credentials from Secrets Manager Connects to the RDS MySQL endpoint

Data is written to or read from the database

Results are returned to the user

Security Model RDS is not publicly accessible RDS only allows inbound traffic from the EC2 security group EC2 retrieves credentials dynamically via IAM role No passwords are stored in code or AMIs



This is intentional friction — security is part of the design.



Expected Deliverables (What You Must Produce) Each student must submit:

A. Infrastructure Proof



EC2 instance running and reachable over HTTP

RDS MySQL instance in the same VPC

Security group rule showing: RDS inbound TCP 3306 Source = EC2 security group (not 0.0.0.0/0) IAM role attached to EC2 allowing Secrets Manager access

B. Application Proof



Successful database initialization

Ability to insert records into RDS

Ability to read records from RDS

C. Verification Evidence



CLI output proving connectivity and configuration

Browser output showing database data

Technical Verification Using AWS CLI (Mandatory) You are expected to prove your work using the CLI — not screenshots alone.

6.1 Verify EC2 Instance aws ec2 describe-instances

--filters "Name=tag:Name,Values=lab-ec2-app"

--query "Reservations\[].Instances\[].InstanceId" Expected: Instance ID returned Instance state = running



6.2 Verify IAM Role Attached to EC2 aws ec2 describe-instances

--instance-ids <INSTANCE\_ID>

--query "Reservations\[].Instances\[].IamInstanceProfile.Arn"



Expected: ARN of an IAM instance profile (not null)



6.3 Verify RDS Instance State aws rds describe-db-instances

--db-instance-identifier lab-mysql

--query "DBInstances\[].DBInstanceStatus"



Expected Available



6.4 Verify RDS Endpoint (Connectivity Target) aws rds describe-db-instances

--db-instance-identifier lab-mysql

--query "DBInstances\[].Endpoint"



Expected: Endpoint address Port 3306



6.5 Verify Security Group Rules (Critical) RDS Security Group Inbound Rules aws ec2 describe-security-groups

--group-names sg-rds-lab

--query "SecurityGroups\[].IpPermissions"



Expected: TCP port 3306 Source referencing EC2 security group ID, not CIDR



6.6 Verify Secrets Manager Access (From EC2) SSH into EC2 and run: aws secretsmanager get-secret-value

--secret-id lab/rds/mysql



Expected: JSON containing: username password host port



If this fails, IAM is misconfigured.



6.7 Verify Database Connectivity (From EC2) Install MySQL client (temporary validation): sudo dnf install -y mysql



Connect: mysql -h <RDS\_ENDPOINT> -u admin -p



Expected: Successful login No timeout or connection refused errors



6.8 Verify Data Path End-to-End From browser: http://<EC2\_PUBLIC\_IP>/init http://<EC2\_PUBLIC\_IP>/add?note=cloud\_labs\_are\_real http://<EC2\_PUBLIC\_IP>/list



Expected: Notes persist across refresh Data survives application restart



Common Failure Modes (And What They Teach)

Failure Lesson Connection timeout Security group or routing issue Access denied IAM or Secrets Manager misconfiguration App starts but DB fails Dependency order matters Works once then breaks Stateless compute vs stateful DB



Every failure here mirrors real production outages.



What This Lab Proves About You If you complete this lab correctly, you can say: “I understand how real AWS applications securely connect compute to managed databases.”

That is a non-trivial claim in the job market.





Lab 1b — Operations, Secrets, and Incident Response Prerequisite: Lab 1a completed and verified



Project Overview (What This Lab Is About) In Lab 1a, you built a working system. In Lab 1b, you will operate, observe, break, and recover that system. You will extend your EC2 → RDS application to include: Dual secret storage AWS Systems Manager Parameter Store AWS Secrets Manager Centralized logging via CloudWatch Logs Automated alarms when database connectivity fails Incident-response actions using previously saved values

This lab simulates what happens after deployment, which is where most real cloud work lives.



Why This Lab Exists (Real-World Context) Most cloud failures are not caused by: Bad code Missing features Wrong instance sizes

They are caused by: Credential issues Secret rotation failures Misconfigured access Silent connectivity loss Poor observability



This lab teaches you how to design for failure, detect it early, and recover using stored configuration data.



Workforce Relevance (Why Employers Care) This Lab Maps Directly to Job Responsibilities In the workforce, you will be expected to: Know where secrets live Understand why multiple secret systems exist Diagnose outages using logs and metrics Respond to incidents without redeploying everything Restore service quickly using known-good configuration

This is the difference between: “I can deploy AWS resources” and “I can keep systems running under pressure”



Parameter Store vs Secrets Manager (Conceptual) You will store database connection values in both systems and intentionally use them during recovery. AWS Systems Manager Parameter Store Best for: Configuration values Non-rotating data Shared application parameters

Supports: Plain text SecureString (encrypted)



Often used for: Feature flags Endpoints Environment configuration



AWS Secrets Manager Best for: Credentials Passwords Rotating secrets



Supports: Automatic rotation Tight audit integration



Often used for: Database passwords API keys



Industry Reality: Many environments use both — intentionally.



What You Are Building in Lab 1b New Capabilities Added

Store DB values in Parameter Store

Store DB credentials in Secrets Manager

Log application DB connection failures to CloudWatch Logs

Create a CloudWatch Alarm that triggers when failures exceed a threshold

Simulate a DB outage or credential failure

Recover the system using saved parameters/secrets without redeploying EC2

This is operations engineering, not app development.



Expected Deliverables (What You Must Produce) A. Configuration Artifacts Parameter Store entries for: DB endpoint DB port DB name

Secrets Manager secret for: DB username/password



B. Observability Application logs visible in CloudWatch Logs Explicit log entries on DB connection failure CloudWatch Alarm configured on error count



C. Incident Response Proof Evidence of a simulated failure Evidence of alarm triggering Evidence of successful recovery using stored values



Technical Verification Using AWS CLI (Required) You must verify everything via CLI — not screenshots alone. What? You think this is easy?

7.1 Verify Parameter Store Values



aws ssm get-parameters \\

&nbsp; --names /lab/db/endpoint /lab/db/port /lab/db/name \\

&nbsp; --with-decryption

Expected: Parameter names returned Correct DB endpoint and port



7.2 Verify Secrets Manager Value



&nbsp; aws secretsmanager get-secret-value \\

&nbsp; --secret-id lab/rds/mysql

Expected: JSON output Fields: username password host port



7.3 Verify EC2 Can Read Both Systems From EC2:



aws ssm get-parameter --name /lab/db/endpoint

aws secretsmanager get-secret-value --secret-id lab/rds/mysql

Expected: Both commands succeed No AccessDeniedException



7.4 Verify CloudWatch Log Group Exists



aws logs describe-log-groups \\

&nbsp; --log-group-name-prefix /aws/ec2/lab-rds-app

Expected: Log group present



7.5 Verify DB Failure Logs Appear Simulate failure (examples): Stop RDS Change DB password in Secrets Manager without updating DB Block SG temporarily



Then check logs:



aws logs filter-log-events \\

&nbsp; --log-group-name /aws/ec2/lab-rds-app \\

&nbsp; --filter-pattern "ERROR"

Expected: Explicit DB connection failure messages



7.6 Verify CloudWatch Alarm



aws cloudwatch describe-alarms \\

&nbsp; --alarm-name-prefix lab-db-connection

Expected: Alarm present State transitions to ALARM during failure



7.7 Incident Recovery Verification After restoring correct credentials or connectivity:



curl http://<EC2\_PUBLIC\_IP>/list

Expected: Application resumes normal operation No redeployment required



Incident-Response Focus (What This Lab Teaches) During recovery, you must: Identify failure source via logs Retrieve correct values from: Parameter Store Secrets Manager Restore service using configuration — not guesswork

This mirrors real on-call workflows.



Common Failure Modes (And Why They Matter) | Failure | Real-World Meaning | | -------------------------- | ------------------------- | | Alarm never fires | Poor observability | | Logs lack detail | Weak incident diagnostics | | EC2 can’t read parameters | IAM misdesign | | Recovery requires redeploy | Fragile architecture |



What Completing Lab 1b Proves If you complete this lab, you can confidently say: “I can operate, monitor, and recover AWS workloads using proper secret management and observability.”



That is mid-level engineer capability, not entry-level.



Reflection Questions: Answer all of these A) Why might Parameter Store still exist alongside Secrets Manager? B) What breaks first during secret rotation? C) Why should alarms be based on symptoms instead of causes?

D) How does this lab reduce mean time to recovery (MTTR)? E) What would you automate next?







Lab 1C — Terraform: EC2 → RDS + Secrets/Params + Observability + Incident Alerts

Purpose

Modern companies do not build AWS by clicking around in the console. They use Infrastructure as Code (IaC) so environments are repeatable, reviewable, auditable, and recoverable.



This repo is intentionally incomplete:



It declares required resources

Students must configure the details (rules, policies, user\_data, app logging, etc.)

Requirements (must exist in Terraform)

VPC, public/private subnets, IGW, NAT, routing

EC2 app host + IAM role/profile

RDS (private) + subnet group + SG with inbound from EC2 SG

Parameter Store values (/lab/db/\*)

Secrets Manager secret (db creds)

CloudWatch log group

CloudWatch alarm (DBConnectionErrors >= 3 per 5 min)

SNS topic + subscription

Student Deliverables

terraform plan output

terraform apply evidence (outputs)

CLI verification commands (from Lab 1b)

Incident runbook execution notes (alarm fired + recovered)

