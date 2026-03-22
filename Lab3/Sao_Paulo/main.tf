locals {
  prefix                    = "liberdade"
  name_prefix               = var.project_name
  env                       = var.env
  megatron_secret_arn_guess = "arn:aws:secretsmanager:${data.aws_region.megatron_region01.id}:${data.aws_caller_identity.megatron_self01.account_id}:secret:${local.name_prefix}/lab1/rds/mysql*"
  # Explanation: This is the roar address — where the galaxy finds your app.
  megatron_fqdn = "${var.app_subdomain}.${var.domain_name}"

  common_tags = {
    Project    = "lab-3a-japan-medical"
    RegionRole = "saopaulo-compute"
    ManagedBy  = "terraform"
    NamePrefix = local.prefix
  }
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

  #  # Re-run user_data script on changes
  user_data_replace_on_change = true

  tags = {
    Name = "${local.name_prefix}-ec2-app01-private"
  }
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
  security_groups = [aws_security_group.megatron_alb_sg01.id]
  subnets         = aws_subnet.megatron_public_subnets[*].id

  # TODO: students can enable access logs to S3 as a stretch goal

  tags = {
    Name = "${var.project_name}-alb01"
  }
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
    path                = "/health"
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
  target_id        = aws_instance.megatron_ec2_01.id
  port             = 3000
  # TODO: students ensure EC2 security group allows inbound from ALB SG on this port (rule above)
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
## Explanation: HTTPS listener is the secure command bridge — TLS termination and forward to private targets.

# #Explanation: HTTPS listener is the real hangar bay — TLS terminates here, then traffic goes to private targets.
#resource "aws_lb_listener" "megatron_http_listener01" {
#  load_balancer_arn = aws_lb.megatron_alb01.arn
#  port              = 80
#  protocol          = "HTTP"

#  default_action {
#    type             = "forward"
#    target_group_arn = aws_lb_target_group.megatron_tg01.arn
#  }
#}