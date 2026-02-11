#######################################################################################################
# Bonus A - Data + Locals
#######################################################################################################
# Explanation: megatron wants to know “who am I in this galaxy?” so ARNs can be scoped properly.
data "aws_caller_identity" "megatron_self01" {}

# Explanation: Region matters—hyperspace lanes change per sector.
data "aws_region" "megatron_region01" {}

#######################################################################################################
# Bonus B - ALB (Public) -> Target Group (Private EC2) + TLS + WAF + Monitoring
# Bonus B - Route53 (Hosted Zone + DNS records + ACM validation + ALIAS to ALB)
#######################################################################################################

locals {
  name_prefix               = var.project_name
  env                       = var.env
  megatron_secret_arn_guess = "arn:aws:secretsmanager:${data.aws_region.megatron_region01.id}:${data.aws_caller_identity.megatron_self01.account_id}:secret:${local.name_prefix}/lab1/rds/mysql*"
  # Explanation: This is the roar address — where the galaxy finds your app.
  megatron_fqdn = "${var.app_subdomain}.${var.domain_name}"

  # Explanation: megatron  needs a home planet—Route53 hosted zone is your DNS territory.
  megatron_zone_name = var.domain_name

  # Explanation: Use either Terraform-managed zone or a pre-existing zone ID (students choose their destiny).
  # Decisoin: Use One local for zone id everywhere
  megatron_zone_id                = var.manage_route53_in_terraform ? try(one(aws_route53_zone.megatron_zone01[*].zone_id), null) : (var.route53_hosted_megatron_zone_id != "" ? var.route53_hosted_megatron_zone_id : null)
  manage_route53_in_terraform     = false
  route53_hosted_megatron_zone_id = "Z08885424JO0XI2RFETE"
  # Explanation: This is the app address that will growl at the galaxy (app.megatron -growl.com).
  megatron_app_fqdn = "${var.app_subdomain}.${var.domain_name}"
}

#######################################################################################################
# VPC + Internet Gateway
#######################################################################################################

# Explanation: megatron needs a hyperlane—this VPC is the Unicron's flight corridor.
resource "aws_vpc" "megatron_vpc01" {
  cidr_block           = var.vpc_cidr
  enable_dns_support   = true
  enable_dns_hostnames = true

  tags = {
    Name = "${local.name_prefix}-vpc01"
  }
}

# Explanation: Even Decepticons need to reach the wider galaxy—IGW is your door to the public internet.
resource "aws_internet_gateway" "megatron_igw01" {
  vpc_id = aws_vpc.megatron_vpc01.id

  tags = {
    Name = "${local.name_prefix}-igw01"
  }
}

#######################################################################################################
# Subnets (Public + Private)
#######################################################################################################

# Explanation: Public subnets are like docking bays—ships can land directly from space (internet).
resource "aws_subnet" "megatron_public_subnets" {
  count                   = length(var.public_subnet_cidrs)
  vpc_id                  = aws_vpc.megatron_vpc01.id
  cidr_block              = var.public_subnet_cidrs[count.index]
  availability_zone       = var.azs[count.index]
  map_public_ip_on_launch = true

  tags = {
    Name = "${local.name_prefix}-public-subnet0${count.index + 1}"
  }
}

# Explanation: Private subnets are the hidden Rebel base—no direct access from the internet.
resource "aws_subnet" "megatron_private_subnets" {
  count             = length(var.private_subnet_cidrs)
  vpc_id            = aws_vpc.megatron_vpc01.id
  cidr_block        = var.private_subnet_cidrs[count.index]
  availability_zone = var.azs[count.index]

  tags = {
    Name = "${local.name_prefix}-private-subnet0${count.index + 1}"
  }
}

#######################################################################################################
# NAT Gateway + EIP
#######################################################################################################

# Explanation: megatron wants the private base to call home—EIP gives the NAT a stable “holonet address.”
resource "aws_eip" "megatron_nat_eip01" {
  domain = "vpc"

  tags = {
    Name = "${local.name_prefix}-nat-eip01"
  }
}

# Explanation: NAT is megatron’s smuggler tunnel—private subnets can reach out without being seen.
resource "aws_nat_gateway" "megatron_nat01" {
  allocation_id = aws_eip.megatron_nat_eip01.id
  subnet_id     = aws_subnet.megatron_public_subnets[0].id # NAT in a public subnet

  tags = {
    Name = "${local.name_prefix}-nat01"
  }

  depends_on = [aws_internet_gateway.megatron_igw01]
}

#######################################################################################################
# Routing (Public + Private Route Tables)
#######################################################################################################

# Explanation: Public route table = “open lanes” to the galaxy via IGW.
resource "aws_route_table" "megatron_public_rt01" {
  vpc_id = aws_vpc.megatron_vpc01.id

  tags = {
    Name = "${local.name_prefix}-public-rt01"
  }
}

# Explanation: This route is the Kessel Run—0.0.0.0/0 goes out the IGW.
resource "aws_route" "megatron_public_default_route" {
  route_table_id         = aws_route_table.megatron_public_rt01.id
  destination_cidr_block = "0.0.0.0/0"
  gateway_id             = aws_internet_gateway.megatron_igw01.id
}

# Explanation: Attach public subnets to the “public lanes.”
resource "aws_route_table_association" "megatron_public_rta" {
  count          = length(aws_subnet.megatron_public_subnets)
  subnet_id      = aws_subnet.megatron_public_subnets[count.index].id
  route_table_id = aws_route_table.megatron_public_rt01.id
}

# Explanation: Private route table = “stay hidden, but still ship energon cubes.”
resource "aws_route_table" "megatron_private_rt01" {
  vpc_id = aws_vpc.megatron_vpc01.id

  tags = {
    Name = "${local.name_prefix}-private-rt01"
  }
}

# Explanation: Private subnets route outbound internet via NAT (megatron-approved stealth).
resource "aws_route" "megatron_private_default_route" {
  route_table_id         = aws_route_table.megatron_private_rt01.id
  destination_cidr_block = "0.0.0.0/0"
  nat_gateway_id         = aws_nat_gateway.megatron_nat01.id
}

# Explanation: Attach private subnets to the “stealth lanes.”
resource "aws_route_table_association" "megatron_private_rta" {
  count          = length(aws_subnet.megatron_private_subnets)
  subnet_id      = aws_subnet.megatron_private_subnets[count.index].id
  route_table_id = aws_route_table.megatron_private_rt01.id
}

########################################################################################################
# Security Group for VPC Interface Endpoints
########################################################################################################

# Explanation: Even endpoints need guards—megatron posts a Wookiee at every airlock.
resource "aws_security_group" "megatron_vpce_sg01" {
  name        = "${local.name_prefix}-vpce-sg01"
  description = "SG for VPC Interface Endpoints"

  #description = "VPC Interface Endpoints security group"
  vpc_id = aws_vpc.megatron_vpc01.id

  lifecycle {
    create_before_destroy = true # This ensures that the SG is recreated before it is destroyed, preventing downtime.
    ignore_changes        = [description]
  }

  # TODO: Students must allow inbound 443 FROM the EC2 SG (or VPC CIDR) to endpoints.
  ingress {
    description     = "HTTPS from private EC2 to interface endpoint"
    from_port       = 443
    to_port         = 443
    protocol        = "tcp"
    security_groups = [aws_security_group.megatron_ec2_sg01.id]
  }
  egress {
    description = "Allow all traffic" # Default outbound rule - return traffic allowed
    from_port   = 0
    to_port     = 0
    protocol    = "-1" # -1 means all protocols
    cidr_blocks = ["0.0.0.0/0"]
  }
  # NOTE: Interface endpoints ENIs receive traffic on 443.

  tags = {
    Name = "${local.name_prefix}-vpce-sg01"
  }
}

######################################################################################################
# Security Groups (EC2 + RDS)
######################################################################################################

# Explanation: EC2 SG is megatron’s bodyguard—only let in what you mean to.
resource "aws_security_group" "megatron_ec2_sg01" {
  name        = "${local.name_prefix}-ec2-sg01"
  description = "EC2 app security group"
  vpc_id      = aws_vpc.megatron_vpc01.id

  lifecycle {
    create_before_destroy = true # This ensures that the SG is recreated before it is destroyed, preventing downtime.
    ignore_changes        = [description]
  }
  # TODO: student adds inbound rules (HTTP 80, SSH 22 from their IP)
  ingress {
    description = "HTTP_inbound"
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
  ingress {
    description = "SSH_inbound"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["174.110.41.221/32"]
  }
  # TODO: student ensures outbound allows DB port to RDS SG (or allow all outbound)
  egress {
    description = "Allow all traffic" # Default outbound rule - allow all outbound traffic
    from_port   = 0
    to_port     = 0
    protocol    = "-1" # -1 means all protocols
    cidr_blocks = ["0.0.0.0/0"]
  }
  tags = {
    Name = "${local.name_prefix}-ec2-sg01"
  }
}

########################################################################################################
# Security Group: ALB
########################################################################################################

# Explanation: The ALB SG is the blast shield — only allow what the Rebellion needs (80/443).
resource "aws_security_group" "megatron_alb_sg01" {
  name        = "${var.project_name}-alb-sg01"
  description = "ALB security group"
  vpc_id      = aws_vpc.megatron_vpc01.id

  # TODO: students add inbound 80/443 from 0.0.0.0/0
  lifecycle {
    create_before_destroy = true # This ensures that the SG is recreated before it is destroyed, preventing downtime.
    ignore_changes        = [description]
  }
  ingress {
    description = "HTTP_inbound"
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
  ingress {
    description = "HTTPS_inbound"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
  # TODO: students set outbound to target group port (usually 80) to private targets
  egress {
    description = "Allow from target group port"
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = [aws_vpc.megatron_vpc01.cidr_block]
  }

  tags = {
    Name = "${var.project_name}-alb-sg01"
  }
}

# Explanation: megatron only opens the hangar door — allow ALB -> EC2 on app port (e.g., 80).
resource "aws_security_group_rule" "megatron_ec2_ingress_from_alb01" {
  type                     = "ingress"
  security_group_id        = aws_security_group.megatron_ec2_sg01.id
  from_port                = 80
  to_port                  = 80
  protocol                 = "tcp"
  source_security_group_id = aws_security_group.megatron_alb_sg01.id

  # TODO: students ensure EC2 app listens on this port (or change to 8080, etc.)
}


########################################################################################################
# Application Load Balancer
########################################################################################################

# Explanation: The ALB is your public customs checkpoint — it speaks TLS and forwards to private targets.
resource "aws_lb" "megatron_alb01" {
  name               = "${var.project_name}-alb01"
  load_balancer_type = "application"
  internal           = false
  ############################################
  # Enable ALB access logs (on the ALB resource)
  ############################################

  # Explanation: Turn on access logs—megatron wants receipts when something goes wrong.
  # NOTE: This is a skeleton patch: students must merge this into aws_lb.megatron_alb01
  # by adding/accessing the `access_logs` block. Terraform does not support "partial" blocks.
  #
  # Add this inside resource "aws_lb" "megatron_alb01" { ... } in bonus_b.tf:
  #
  access_logs {
    bucket  = aws_s3_bucket.megatron_alb_logs_bucket01[0].bucket
    prefix  = var.alb_access_logs_prefix
    enabled = var.enable_alb_access_logs
  }

  depends_on      = [aws_s3_bucket_policy.megatron_alb_logs_policy01]
  security_groups = [aws_security_group.megatron_alb_sg01.id]
  subnets         = aws_subnet.megatron_public_subnets[*].id

  # TODO: students can enable access logs to S3 as a stretch goal

  tags = {
    Name = "${var.project_name}-alb01"
  }
}

########################################################################################################
# VPC Endpoint - S3 (Gateway)
########################################################################################################

# Explanation: S3 is the supply depot—without this, your private world starves (updates, artifacts, logs).
resource "aws_vpc_endpoint" "megatron_vpce_s3_gw01" {
  vpc_id            = aws_vpc.megatron_vpc01.id
  service_name      = "com.amazonaws.${data.aws_region.megatron_region01.id}.s3"
  vpc_endpoint_type = "Gateway"

  route_table_ids = [
    aws_route_table.megatron_private_rt01.id
  ]

  tags = {
    Name = "${local.name_prefix}-vpce-s3-gw01"
  }
}

########################################################################################################
# VPC Endpoints - SSM (Interface)
########################################################################################################

# Explanation: SSM is your Force choke—remote control without SSH, and nobody sees your keys.
resource "aws_vpc_endpoint" "megatron_vpce_ssm01" {
  vpc_id              = aws_vpc.megatron_vpc01.id
  service_name        = "com.amazonaws.${data.aws_region.megatron_region01.id}.ssm"
  vpc_endpoint_type   = "Interface"
  private_dns_enabled = true

  subnet_ids         = aws_subnet.megatron_private_subnets[*].id
  security_group_ids = [aws_security_group.megatron_vpce_sg01.id]

  tags = {
    Name = "${local.name_prefix}-vpce-ssm01"
  }
}
# Explanation: ec2messages is the Starscream messenger—SSM sessions won’t work without it.
resource "aws_vpc_endpoint" "Megatron_vpce_ec2messages01" {
  vpc_id              = aws_vpc.megatron_vpc01.id
  service_name        = "com.amazonaws.${data.aws_region.megatron_region01.id}.ec2messages"
  vpc_endpoint_type   = "Interface"
  private_dns_enabled = true

  subnet_ids         = aws_subnet.megatron_private_subnets[*].id
  security_group_ids = [aws_security_group.megatron_vpce_sg01.id]

  tags = {
    Name = "${local.name_prefix}-vpce-ec2messages01"
  }
}

# Explanation: ssmmessages is the holonet channel—Session Manager needs it to talk back.
resource "aws_vpc_endpoint" "megatron_vpce_ssmmessages01" {
  vpc_id              = aws_vpc.megatron_vpc01.id
  service_name        = "com.amazonaws.${data.aws_region.megatron_region01.id}.ssmmessages"
  vpc_endpoint_type   = "Interface"
  private_dns_enabled = true

  subnet_ids         = aws_subnet.megatron_private_subnets[*].id
  security_group_ids = [aws_security_group.megatron_vpce_sg01.id]

  tags = {
    Name = "${local.name_prefix}-vpce-ssmmessages01"
  }
}

########################################################################################################
# Security Group: Setting up RDS (MySQL) Security Group 
########################################################################################################
# Explanation: RDS SG is the Rebel vault—only the app server gets a keycard.
resource "aws_security_group" "megatron_rds_sg01" {
  name        = "${local.name_prefix}-rds-sg01"
  description = "RDS MySQL access from EC2 only"
  vpc_id      = aws_vpc.megatron_vpc01.id

  lifecycle {
    create_before_destroy = true # This ensures that the SG is recreated before it is destroyed, preventing downtime.
    ignore_changes        = [description]
  }
  # TODO: student adds inbound MySQL 3306 from aws_security_group.megatron_ec2_sg01.id
  ingress {
    description     = "MySQL_inbound_from_EC2"
    from_port       = 3306
    to_port         = 3306
    protocol        = "tcp"
    security_groups = [aws_security_group.megatron_ec2_sg01.id]
  }
  egress {
    description = "Allow all traffic" # Default outbound rule - allow all outbound traffic
    from_port   = 0
    to_port     = 0
    protocol    = "-1" # -1 means all protocols
    cidr_blocks = ["0.0.0.0/0"]
  }
  tags = {
    Name = "${local.name_prefix}-rds-sg01"
  }
}

#######################################################################################################
# RDS Subnet Group
#######################################################################################################

# Explanation: RDS hides in private subnets like the Rebel base on Hoth—cold, quiet, and not public.
resource "aws_db_subnet_group" "megatron_rds_subnet_group01" {
  name       = "${local.name_prefix}-rds-subnet-group01"
  subnet_ids = aws_subnet.megatron_private_subnets[*].id

  lifecycle {
    create_before_destroy = true # This ensures that the SG is recreated before it is destroyed, preventing downtime.
  }

  tags = {
    Name = "${local.name_prefix}-rds-subnet-group01"
  }
}

#######################################################################################################
# RDS Instance (MySQL)
#######################################################################################################

# Explanation: This is the holocron of state—your relational data lives here, not on the EC2.
resource "aws_db_instance" "megatron_rds01" {
  identifier        = "${local.name_prefix}-rds01"
  engine            = var.db_engine
  instance_class    = var.db_instance_class
  allocated_storage = 20
  db_name           = var.db_name
  username          = var.db_username
  password          = var.db_password

  db_subnet_group_name   = aws_db_subnet_group.megatron_rds_subnet_group01.name
  vpc_security_group_ids = [aws_security_group.megatron_rds_sg01.id]

  publicly_accessible = false
  skip_final_snapshot = true

  # TODO: student sets multi_az / backups / monitoring as stretch goals

  tags = {
    Name = "${local.name_prefix}-rds01"
  }
}

#######################################################################################################
# IAM Role + Instance Profile for EC2
#######################################################################################################

# Explanation: megatron refuses to carry static keys—this role lets EC2 assume permissions safely.
resource "aws_iam_role" "megatron_ec2_role01" {
  name = "${local.name_prefix}-ec2-role01"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })
}

# Explanation: These policies are your Decepticons toolbelt—tighten them (least privilege) as a stretch goal.
resource "aws_iam_role_policy_attachment" "megatron_ec2_ssm_attach" {
  role       = aws_iam_role.megatron_ec2_role01.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
}

# Explanation: EC2 must read secrets/params during recovery—give it access (students should scope it down).
resource "aws_iam_role_policy_attachment" "megatron_ec2_secrets_attach" {
  role       = aws_iam_role.megatron_ec2_role01.name
  policy_arn = "arn:aws:iam::aws:policy/SecretsManagerReadWrite" # TODO: student replaces w/ least privilege
}

# Explanation: CloudWatch logs are the “ship’s black box”—you need them when things explode.
resource "aws_iam_role_policy_attachment" "megatron_ec2_cw_attach" {
  role       = aws_iam_role.megatron_ec2_role01.name
  policy_arn = "arn:aws:iam::aws:policy/CloudWatchAgentServerPolicy"
}

# Explanation: Instance profile is the harness that straps the role onto the EC2 like bandolier ammo.
resource "aws_iam_instance_profile" "megatron_instance_profile01" {
  name = "${local.name_prefix}-instance-profile01"
  role = aws_iam_role.megatron_ec2_role01.name
}

#######################################################################################################
# EC2 Instance (App Host)
#lab1c # Move EC2 into PRIVATE subnet (no public IP)
#######################################################################################################

# Explanation: This is your “Soundwave box” —it talks to RDS database and complains loudly when the DB is down.
resource "aws_instance" "megatron_ec2_01" {
  ami                    = var.ec2_ami_id
  instance_type          = var.ec2_instance_type
  subnet_id              = aws_subnet.megatron_private_subnets[0].id
  vpc_security_group_ids = [aws_security_group.megatron_ec2_sg01.id]
  iam_instance_profile   = aws_iam_instance_profile.megatron_instance_profile01.name

  # TODO: student supplies user_data to install app + CW agent + configure log shipping
  # user_data = file("${path.module}/user_data.sh") #no longer needed since we are using a template
  # This shell script template that Terraform fills in before sending it to EC2

  user_data = templatefile("${path.module}/user_data.sh.tftpl", {
    app_bootstrap = file("${path.module}/user_data.sh")               # Application install/config script
    cw_bootstrap  = file("${path.module}/cloudwatch_agent_config.sh") # CloudWatch Agent install/config script
  })

  # Re-run user_data script on changes
  user_data_replace_on_change = true

  tags = {
    Name = "${local.name_prefix}-ec2-app01-private"
  }
}
#######################################################################################################
# Adding TLS Key Pair (for app use,e.g., DB encryption)  #Not required by THEO but useful for PRACTICE
#######################################################################################################
resource "tls_private_key" "MegaKey" {
  algorithm = "RSA"
  rsa_bits  = 2048
}

data "tls_public_key" "MegaKey" {
  private_key_pem = tls_private_key.MegaKey.private_key_pem
}

output "private_key" {
  value     = tls_private_key.MegaKey.private_key_pem
  sensitive = true
}

output "public_key" {
  value = data.tls_public_key.MegaKey.public_key_openssh
}

#######################################################################################################
# Parameter Store (SSM Parameters)
#######################################################################################################

# Explanation: Parameter Store is megatron’s map—endpoints and config live here for fast recovery.
resource "aws_ssm_parameter" "megatron_db_endpoint_param" {
  name      = "/lab/db/endpoint"
  type      = "String"
  value     = aws_db_instance.megatron_rds01.address
  overwrite = "true"

  tags = {
    Name = "${local.name_prefix}-param-db-endpoint"
  }
}

# Explanation: Ports are boring, but even Decepticons need to know which door number to kick in.
resource "aws_ssm_parameter" "megatron_db_port_param" {
  name      = "/lab/db/port"
  type      = "String"
  value     = tostring(aws_db_instance.megatron_rds01.port)
  overwrite = "true"

  tags = {
    Name = "${local.name_prefix}-param-db-port"
  }
}

# Explanation: DB name is the label on the crate—without it, you’re rummaging in the dark.
resource "aws_ssm_parameter" "megatron_db_name_param" {
  name      = "/lab/db/name"
  type      = "String"
  value     = var.db_name
  overwrite = "true"

  tags = {
    Name = "${local.name_prefix}-param-db-name"
  }
}

#######################################################################################################
# Secrets Manager (DB Credentials)
#######################################################################################################

resource "random_id" "suffix" { # to make secret name unique with limited length
  byte_length = 3
}

#Explanation: Secrets Manager is megatron’s locked holster—credentials go here, not in code.
resource "aws_secretsmanager_secret" "megatron_db_secret01" {
  # name = "${local.name_prefix}/${local.env}/rds/mysql-${random_id.suffix.hex}"
  name        = "${local.name_prefix}/${local.env}/rds/mysql"
  description = "RDS MySQL credentials for ${local.name_prefix} app"
  tags = {
    Name = "${local.name_prefix}-db-secret01"
  }
  lifecycle {
    create_before_destroy = true # This ensures that the secret is recreated before it is destroyed, preventing downtime.
  }
  #Exist secret will be destroy immediately when tf destroy is executed to prevent error when new secret is created
  recovery_window_in_days = 0
}
#Explanation: Secret payload—students should align this structure with their app (and support rotation later).
resource "aws_secretsmanager_secret_version" "megatron_db_secret_version01" {
  secret_id = aws_secretsmanager_secret.megatron_db_secret01.id

  secret_string = jsonencode({
    username = var.db_username
    password = var.db_password
    host     = aws_db_instance.megatron_rds01.address
    port     = aws_db_instance.megatron_rds01.port
    dbname   = var.db_name
  })
}

########################################################################################################
# VPC Endpoint - Secrets Manager (Interface)
########################################################################################################

# Explanation: Secrets Manager is the locked vault—megatron doesn’t put passwords on sticky notes.
resource "aws_vpc_endpoint" "megatron_vpce_secrets01" {
  vpc_id              = aws_vpc.megatron_vpc01.id
  service_name        = "com.amazonaws.${data.aws_region.megatron_region01.id}.secretsmanager"
  vpc_endpoint_type   = "Interface"
  private_dns_enabled = true

  subnet_ids         = aws_subnet.megatron_private_subnets[*].id
  security_group_ids = [aws_security_group.megatron_vpce_sg01.id]

  tags = {
    Name = "${local.name_prefix}-vpce-secrets01"
  }
}


#######################################################################################################
# CloudWatch Logs (Log Group)
#######################################################################################################

# Explanation: When UniCron is on fire, logs tell you *which* wire sparked—ship them centrally.
resource "aws_cloudwatch_log_group" "megatron_log_group01" {
  name              = "/aws/ec2/${local.name_prefix}-cwagent"
  retention_in_days = 7

  tags = {
    Name = "${local.name_prefix}-log-group01"
  }
}

#######################################################################################################
# Custom Metric + Alarm (Skeleton)
#######################################################################################################

# Explanation: Metrics are megatron’s growls—when they spike, something is wrong.
# NOTE: Students must emit the metric from app/agent; this just declares the alarm.
resource "aws_cloudwatch_metric_alarm" "megatron_db_alarm01" {
  alarm_name          = "${local.name_prefix}-db-connection-failure"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = 1
  metric_name         = "DBConnectionErrors"
  namespace           = "Lab/RDSApp"
  period              = 300
  statistic           = "Sum"
  threshold           = 3
  treat_missing_data  = "notBreaching" # optional but nice to avoid alarms stuck in INSUFFICIENT_DATA

  # CloudWatch won’t know which DB instance you mean without dimension, and you often get “no data” / never alarms
  #dimensions = {
  #   DBInstanceIdentifier = aws_db_instance.my_instance_rds.id
  # }

  alarm_actions = [aws_sns_topic.megatron_sns_topic01.arn]

  tags = {
    Name = "${local.name_prefix}-alarm-db-fail"
  }
}

########################################################################################################
# CloudWatch Alarm: ALB 5xx -> SNS
########################################################################################################

# Explanation: When the ALB starts throwing 5xx, that’s Devastator coughing — page the on-call bot.
resource "aws_cloudwatch_metric_alarm" "megatron_alb_5xx_alarm01" {
  alarm_name          = "${var.project_name}-alb-5xx-alarm01"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = var.alb_5xx_evaluation_periods
  threshold           = var.alb_5xx_threshold
  period              = var.alb_5xx_period_seconds
  statistic           = "Sum"

  namespace   = "AWS/ApplicationELB"
  metric_name = "HTTPCode_ELB_5XX_Count"

  dimensions = {
    LoadBalancer = aws_lb.megatron_alb01.arn_suffix
  }

  alarm_actions = [aws_sns_topic.megatron_sns_topic01.arn]

  tags = {
    Name = "${var.project_name}-alb-5xx-alarm01"
  }
}

######################################################################################################
# CloudWatch Dashboard (Skeleton)
######################################################################################################

# Explanation: Dashboards are your cockpit HUD — megatronwants dials, not vibes.
resource "aws_cloudwatch_dashboard" "megatron_dashboard01" {
  dashboard_name = "${var.project_name}-dashboard01"

  # TODO: students can expand widgets; this is a minimal workable skeleton
  dashboard_body = jsonencode({
    widgets = [
      {
        type   = "metric"
        x      = 0
        y      = 0
        width  = 12
        height = 6
        properties = {
          metrics = [
            ["AWS/ApplicationELB", "RequestCount", "LoadBalancer", aws_lb.megatron_alb01.arn_suffix],
            [".", "HTTPCode_ELB_5XX_Count", ".", aws_lb.megatron_alb01.arn_suffix]
          ]
          period = 300
          stat   = "Sum"
          region = var.aws_region
          title  = "megatronALB: Requests + 5XX"
        }
      },
      {
        type   = "metric"
        x      = 12
        y      = 0
        width  = 12
        height = 6
        properties = {
          metrics = [
            ["AWS/ApplicationELB", "TargetResponseTime", "LoadBalancer", aws_lb.megatron_alb01.arn_suffix]
          ]
          period = 300
          stat   = "Average"
          region = var.aws_region
          title  = "megatronALB: Target Response Time"
        }
      }
    ]
  })
}

######################################################################################################
# VPC Endpoint - CloudWatch Logs (Interface)
######################################################################################################

# Explanation: CloudWatch Logs is the ship’s black box—megatron wants crash data, always.
resource "aws_vpc_endpoint" "megatron_vpce_logs01" {
  vpc_id              = aws_vpc.megatron_vpc01.id
  service_name        = "com.amazonaws.${data.aws_region.megatron_region01.id}.logs"
  vpc_endpoint_type   = "Interface"
  private_dns_enabled = true

  subnet_ids         = aws_subnet.megatron_private_subnets[*].id
  security_group_ids = [aws_security_group.megatron_vpce_sg01.id]

  tags = {
    Name = "${local.name_prefix}-vpce-logs01"
  }
}

#######################################################################################################
# SNS (PagerDuty simulation)
#######################################################################################################

# Explanation: SNS is the distress beacon—when the DB dies, the galaxy (your inbox) must hear about it.
resource "aws_sns_topic" "megatron_sns_topic01" {
  name = "${local.name_prefix}-db-incidents"
}

# Explanation: Email subscription = “poor man’s PagerDuty”—still enough to wake you up at 3AM.
resource "aws_sns_topic_subscription" "megatron_sns_sub01" {
  topic_arn = aws_sns_topic.megatron_sns_topic01.arn
  protocol  = "email"
  endpoint  = var.sns_email_endpoint
}

#######################################################################################################
# (Optional but realistic) VPC Endpoints (Skeleton)
#######################################################################################################

# Explanation: Endpoints keep traffic inside AWS like hyperspace lanes—less exposure, more control.
# TODO: students can add endpoints for SSM, Logs, Secrets Manager if doing “no public egress” variant.
# resource "aws_vpc_endpoint" "megatron_vpce_ssm" { ... }

########################################################################################################
# Least-Privilege IAM (BONUS A)
########################################################################################################

# Explanation: megatron doesn’t hand out the Falcon keys—this policy scopes reads to your lab paths only.
resource "aws_iam_policy" "megatron_leastpriv_read_params01" {
  name        = "${local.name_prefix}-lp-ssm-read01"
  description = "Least-privilege read for SSM Parameter Store under /lab1/rds/mysql/*"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "ReadLabDbParams"
        Effect = "Allow"
        Action = [
          "ssm:GetParameter",
          "ssm:GetParameters",
          "ssm:GetParametersByPath"
        ]
        Resource = [
          "arn:aws:ssm:${data.aws_region.megatron_region01.id}:${data.aws_caller_identity.megatron_self01.account_id}:parameter/lab1/rds/mysql*"
        ]
      }
    ]
  })
}
# Explanation: megatron only opens *this* vault—GetSecretValue for only your secret (not the whole planet).
resource "aws_iam_policy" "megatron_leastpriv_read_secret01" {
  name        = "${local.name_prefix}-lp-secrets-read01"
  description = "Least-privilege read for the lab DB secret"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "ReadOnlyLabSecret"
        Effect = "Allow"
        Action = [
          "secretsmanager:GetSecretValue",
          "secretsmanager:DescribeSecret"
        ]
        Resource = local.megatron_secret_arn_guess
      }
    ]
  })
}
########################################################################################
# Explanation: ALB is the megatron’s command bridge—public face, private backend.
########################################################################################
# Target Group + Attachment
########################################################################################

# Explanation: Target groups are megatron’s “who do I forward to?” list — private EC2 lives here.
resource "aws_lb_target_group" "megatron_tg01" {
  name     = "${var.project_name}-tg01"
  port     = 80
  protocol = "HTTP"
  vpc_id   = aws_vpc.megatron_vpc01.id

  # TODO: students set health check path to something real (e.g., /health)
  health_check {
    enabled             = true
    interval            = 30
    path                = "/"
    port                = "traffic-port"
    protocol            = "HTTP"
    healthy_threshold   = 2
    unhealthy_threshold = 2
    timeout             = 5
    matcher             = "200-399"
  }

  tags = {
    Name = "${var.project_name}-tg01"
  }
}
# Explanation: megatron personally introduces the ALB to the private EC2 — “this is my friend, don’t shoot.”
resource "aws_lb_target_group_attachment" "megatron_tg_attach01" {
  target_group_arn = aws_lb_target_group.megatron_tg01.arn
  #target_id        = aws_instance.megatron_ec2_01_private.id
  target_id = aws_instance.megatron_ec2_01.id
  port      = 80
  # TODO: students ensure EC2 security group allows inbound from ALB SG on this port (rule above)
}
########################################################################################
# ACM Certificate (TLS) for app.technology4gold.com
########################################################################################

# Cert covers apex + app
resource "aws_acm_certificate" "megatron_acm_cert01" {
  domain_name               = var.domain_name       # technology4gold.com
  subject_alternative_names = [local.megatron_fqdn] # app.technology4gold.com
  validation_method         = var.certificate_validation_method

  lifecycle {
    create_before_destroy = true
  }

  tags = {
    Name = "${var.project_name}-acm-cert01"
  }
}


# Explanation: The zone  is the throne room—megatron-technology4gold.com itself should lead to the ALB.
resource "aws_route53_record" "megatron_app_alias01" {
  #zone_id = aws_route53_zone.megatron_zone01[0].zone_id
  zone_id = local.megatron_zone_id
  #name    = var.domain_name
  name = "app.${var.domain_name}"
  type = "A"
  alias {
    name                   = aws_lb.megatron_alb01.dns_name
    zone_id                = aws_lb.megatron_alb01.zone_id
    evaluate_target_health = true
  }
}

############################################
# Bonus B - Route53 Zone Apex + ALB Access Logs to S3
############################################

############################################
# Route53: Zone Apex (root domain) -> ALB
############################################

# Explanation: The zone apex is the throne room—technology4gold.com itself should lead to the ALB.
resource "aws_route53_record" "megatron_apex_alias01" {
  zone_id = local.megatron_zone_id
  name    = var.domain_name
  type    = "A"

  alias {
    name                   = aws_lb.megatron_alb01.dns_name
    zone_id                = aws_lb.megatron_alb01.zone_id
    evaluate_target_health = true
  }
}

############################################
# S3 bucket for ALB access logs
############################################

# Explanation: This bucket is megatron’s log vault—every visitor to the ALB leaves footprints here.
resource "aws_s3_bucket" "megatron_alb_logs_bucket01" {
  count = var.enable_alb_access_logs ? 1 : 0

  # NOTE: Bucket must be in same region as ALB (you are, if provider region matches ALB region)
  bucket = "${var.project_name}-alb-logs-${data.aws_caller_identity.megatron_self01.account_id}"

  # Labs: makes destroy easier if logs exist
  force_destroy = true

  tags = {
    Name = "${var.project_name}-alb-logs-bucket01"
  }
}

# Explanation: Block public access—megatron does not publish the ship’s black box to the galaxy.
resource "aws_s3_bucket_public_access_block" "megatron_alb_logs_pab01" {
  count = var.enable_alb_access_logs ? 1 : 0

  bucket                  = aws_s3_bucket.megatron_alb_logs_bucket01[0].id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# Explanation: Bucket ownership controls prevent log delivery chaos—megatron likes clean chain-of-custody.
resource "aws_s3_bucket_ownership_controls" "megatron_alb_logs_owner01" {
  count = var.enable_alb_access_logs ? 1 : 0

  bucket = aws_s3_bucket.megatron_alb_logs_bucket01[0].id
  rule {
    object_ownership = "BucketOwnerPreferred"
  }
}

# Explanation: TLS-only—megatron growls at plaintext and throws it out an airlock.
resource "aws_s3_bucket_policy" "megatron_alb_logs_policy01" {
  count = var.enable_alb_access_logs ? 1 : 0

  bucket = aws_s3_bucket.megatron_alb_logs_bucket01[0].id

  # NOTE: This is a skeleton. Students may need to adjust for region/account specifics.
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "DenyInsecureTransport"
        Effect    = "Deny"
        Principal = "*"
        Action    = "s3:*"
        Resource = [
          aws_s3_bucket.megatron_alb_logs_bucket01[0].arn,
          "${aws_s3_bucket.megatron_alb_logs_bucket01[0].arn}/*"
        ]
        Condition = {
          Bool = { "aws:SecureTransport" = "false" }
        }
      },
      {
        Sid    = "AllowELBPutObject"
        Effect = "Allow"
        Principal = {
          Service = "logdelivery.elasticloadbalancing.amazonaws.com"
        }
        Action   = "s3:PutObject"
        Resource = "${aws_s3_bucket.megatron_alb_logs_bucket01[0].arn}/${var.alb_access_logs_prefix}/AWSLogs/${data.aws_caller_identity.megatron_self01.account_id}/*"
      }
    ]
  })
}


############################################
# Hosted Zone (optional creation)
############################################

# Explanation: A hosted zone is like claiming Kashyyyk in DNS—names here become law across the galaxy.
resource "aws_route53_zone" "megatron_zone01" {
  count = var.manage_route53_in_terraform ? 1 : 0
  name  = local.megatron_zone_name
  #name  = var.domain_name

  tags = {
    Name = "${var.project_name}-zone01"
  }
}


############################################
# ACM DNS Validation Records
############################################

# Explanation: ACM asks “prove you own this planet”—DNS validation is megatron roaring in the right place.
resource "aws_route53_record" "megatron_acm_validation_records01" {
  allow_overwrite = true

  for_each = var.certificate_validation_method == "DNS" ? {
    for dvo in aws_acm_certificate.megatron_acm_cert01.domain_validation_options :
    dvo.domain_name => {
      name   = dvo.resource_record_name
      type   = dvo.resource_record_type
      record = dvo.resource_record_value
    }
  } : {}

  zone_id = local.megatron_zone_id
  name    = each.value.name
  type    = each.value.type
  ttl     = 60

  records = [each.value.record]
}

# Explanation: This ties the “proof record” back to ACM—megatron gets his green checkmark for TLS.
resource "aws_acm_certificate_validation" "megatron_acm_validation01_dns_bonus" {
  count = var.certificate_validation_method == "DNS" ? 1 : 0
  #certificate_arn = aws_acm_certificate.megatron_acm_cert01.arn
  certificate_arn = aws_acm_certificate_validation.megatron_acm_validation01.certificate_arn

  validation_record_fqdns = [
    for r in aws_route53_record.megatron_acm_validation_records01 : r.fqdn
  ]
}

# Explanation: Once validated, ACM becomes the “green checkmark” — until then, ALB HTTPS won’t work.
resource "aws_acm_certificate_validation" "megatron_acm_validation01" {
  certificate_arn = aws_acm_certificate.megatron_acm_cert01.arn

  # TODO: if using DNS validation, students must pass validation_record_fqdns
  # validation_record_fqdns = [aws_route53_record.megatron_acm_validation.fqdn]
}

########################################################################################################
# ALB Listeners: HTTP -> HTTPS redirect, HTTPS -> TG
########################################################################################################

# Explanation: HTTP listener is the decoy airlock — it redirects everyone to the secure entrance.
resource "aws_lb_listener" "megatron_http_listener01" {
  load_balancer_arn = aws_lb.megatron_alb01.arn
  port              = 80
  protocol          = "HTTP"

  default_action {
    type = "redirect"
    redirect {
      port        = "443"
      protocol    = "HTTPS"
      status_code = "HTTP_301"
    }
  }
}
# Explanation: HTTPS listener is the secure command bridge — TLS termination and forward to private targets.

# Explanation: HTTPS listener is the real hangar bay — TLS terminates here, then traffic goes to private targets.
resource "aws_lb_listener" "megatron_https_listener01" {
  load_balancer_arn = aws_lb.megatron_alb01.arn
  port              = 443
  protocol          = "HTTPS"
  ssl_policy        = "ELBSecurityPolicy-TLS13-1-2-2021-06"
  certificate_arn   = aws_acm_certificate_validation.megatron_acm_validation01.certificate_arn

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.megatron_tg01.arn
  }

  depends_on = [aws_acm_certificate_validation.megatron_acm_validation01]
}

########################################################################################################
# WAFv2 Web ACL (Basic managed rules)
########################################################################################################

# Explanation: WAF is the shield generator — it blocks the cheap blaster fire before it hits your ALB.
resource "aws_wafv2_web_acl" "megatron_waf01" {
  count = var.enable_waf ? 1 : 0

  name  = "${var.project_name}-waf01"
  scope = "REGIONAL"

  default_action {
    allow {}
  }

  visibility_config {
    cloudwatch_metrics_enabled = true
    metric_name                = "${var.project_name}-waf01"
    sampled_requests_enabled   = true
  }

  # Explanation: AWS managed rules are like hiring Rebel commandos — they’ve seen every trick.
  rule {
    name     = "AWSManagedRulesCommonRuleSet"
    priority = 1

    override_action {
      none {}
    }

    statement {
      managed_rule_group_statement {
        name        = "AWSManagedRulesCommonRuleSet"
        vendor_name = "AWS"
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "${var.project_name}-waf-common"
      sampled_requests_enabled   = true
    }
  }

  tags = {
    Name = "${var.project_name}-waf01"
  }
}

# Explanation: Attach the shield generator to the customs checkpoint — ALB is now protected.
resource "aws_wafv2_web_acl_association" "megatron_waf_assoc01" {
  count = var.enable_waf ? 1 : 0

  resource_arn = aws_lb.megatron_alb01.arn
  web_acl_arn  = aws_wafv2_web_acl.megatron_waf01[0].arn
}
############################################
# Bonus B - WAF Logging (CloudWatch Logs OR S3 OR Firehose)
# One destination per Web ACL, choose via var.waf_log_destination.
############################################

############################################
# Option 1: CloudWatch Logs destination
############################################

# Explanation: WAF logs in CloudWatch are your “blaster-cam footage”—fast search, fast triage, fast truth.
resource "aws_cloudwatch_log_group" "megatron_waf_log_group01" {
  count = var.waf_log_destination == "cloudwatch" ? 1 : 0

  # NOTE: AWS requires WAF log destination names start with aws-waf-logs- (students must not rename this).
  name              = "aws-waf-logs-${var.project_name}-webacl01"
  retention_in_days = var.waf_log_retention_days

  tags = {
    Name = "${var.project_name}-waf-log-group01"
  }
}

# Explanation: This wire connects the shield generator to the black box—WAF -> CloudWatch Logs.
resource "aws_wafv2_web_acl_logging_configuration" "megatron_waf_logging01" {
  count = var.enable_waf && var.waf_log_destination == "cloudwatch" ? 1 : 0

  resource_arn = aws_wafv2_web_acl.megatron_waf01[0].arn
  log_destination_configs = [
    aws_cloudwatch_log_group.megatron_waf_log_group01[0].arn
  ]

  # TODO: Students can add redacted_fields (authorization headers, cookies, etc.) as a stretch goal.
  # redacted_fields { ... }

  depends_on = [aws_wafv2_web_acl.megatron_waf01]
}

############################################
# Option 2: S3 destination (direct)
############################################

# Explanation: S3 WAF logs are the long-term archive—megatron likes receipts that survive dashboards.
resource "aws_s3_bucket" "megatron_waf_logs_bucket01" {
  count = var.waf_log_destination == "s3" ? 1 : 0

  bucket = "aws-waf-logs-${var.project_name}-${data.aws_caller_identity.megatron_self01.account_id}"

  tags = {
    Name = "${var.project_name}-waf-logs-bucket01"
  }
}

# Explanation: Public access blocked—WAF logs are not a bedtime story for the entire internet.
resource "aws_s3_bucket_public_access_block" "megatron_waf_logs_pab01" {
  count = var.waf_log_destination == "s3" ? 1 : 0

  bucket                  = aws_s3_bucket.megatron_waf_logs_bucket01[0].id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# Explanation: Connect shield generator to archive vault—WAF -> S3.
resource "aws_wafv2_web_acl_logging_configuration" "megatron_waf_logging_s3_01" {
  count = var.enable_waf && var.waf_log_destination == "s3" ? 1 : 0

  resource_arn = aws_wafv2_web_acl.megatron_waf01[0].arn
  log_destination_configs = [
    aws_s3_bucket.megatron_waf_logs_bucket01[0].arn
  ]

  depends_on = [aws_wafv2_web_acl.megatron_waf01]
}

############################################
# Option 3: Firehose destination (classic “stream then store”)
############################################

# Explanation: Firehose is the conveyor belt—WAF logs ride it to storage (and can fork to SIEM later).
resource "aws_s3_bucket" "megatron_firehose_waf_dest_bucket01" {
  count = var.waf_log_destination == "firehose" ? 1 : 0

  bucket = "${var.project_name}-waf-firehose-dest-${data.aws_caller_identity.megatron_self01.account_id}"

  tags = {
    Name = "${var.project_name}-waf-firehose-dest-bucket01"
  }
}

# Explanation: Firehose needs a role—megatron doesn’t let random droids write into storage.
resource "aws_iam_role" "megatron_firehose_role01" {
  count = var.waf_log_destination == "firehose" ? 1 : 0
  name  = "${var.project_name}-firehose-role01"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "firehose.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })
}

# Explanation: Minimal permissions—allow Firehose to put objects into the destination bucket.
resource "aws_iam_role_policy" "megatron_firehose_policy01" {
  count = var.waf_log_destination == "firehose" ? 1 : 0
  name  = "${var.project_name}-firehose-policy01"
  role  = aws_iam_role.megatron_firehose_role01[0].id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "s3:AbortMultipartUpload",
          "s3:GetBucketLocation",
          "s3:GetObject",
          "s3:ListBucket",
          "s3:ListBucketMultipartUploads",
          "s3:PutObject"
        ]
        Resource = [
          aws_s3_bucket.megatron_firehose_waf_dest_bucket01[0].arn,
          "${aws_s3_bucket.megatron_firehose_waf_dest_bucket01[0].arn}/*"
        ]
      }
    ]
  })
}

# Explanation: The delivery stream is the belt itself—logs move from WAF -> Firehose -> S3.
resource "aws_kinesis_firehose_delivery_stream" "megatron_waf_firehose01" {
  count       = var.waf_log_destination == "firehose" ? 1 : 0
  name        = "aws-waf-logs-${var.project_name}-firehose01"
  destination = "extended_s3"

  extended_s3_configuration {
    role_arn   = aws_iam_role.megatron_firehose_role01[0].arn
    bucket_arn = aws_s3_bucket.megatron_firehose_waf_dest_bucket01[0].arn
    prefix     = "waf-logs/"
  }
}

# Explanation: Connect shield generator to conveyor belt—WAF -> Firehose stream.
resource "aws_wafv2_web_acl_logging_configuration" "megatron_waf_logging_firehose01" {
  count = var.enable_waf && var.waf_log_destination == "firehose" ? 1 : 0

  resource_arn = aws_wafv2_web_acl.megatron_waf01[0].arn
  log_destination_configs = [
    aws_kinesis_firehose_delivery_stream.megatron_waf_firehose01[0].arn
  ]

  depends_on = [aws_wafv2_web_acl.megatron_waf01]
}