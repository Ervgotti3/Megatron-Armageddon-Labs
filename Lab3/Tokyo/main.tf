locals {
  prefix                    = "shinjuku"
  name_prefix               = var.project_name
  env                       = var.env
  megatron_secret_arn_guess = "arn:aws:secretsmanager:${data.aws_region.megatron_region01.id}:${data.aws_caller_identity.megatron_self01.account_id}:secret:${local.name_prefix}/lab1/rds/mysql*"
  # Explanation: This is the roar address — where the galaxy finds your app.
  megatron_fqdn = "${var.app_subdomain}.${var.domain_name}"

  common_tags = {
    Project    = "lab-3a-japan-medical"
    RegionRole = "tokyo-primary"
    ManagedBy  = "terraform"
    NamePrefix = local.prefix
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

########################################################################################################
# Security Group: Setting up RDS (MySQL) Security Group 
########################################################################################################
resource "aws_security_group" "megatron_rds_sg01" {
  name        = "${local.prefix}-rds-sg01"
  description = "RDS security group"
  vpc_id      = aws_vpc.megatron_vpc01.id

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = merge(local.common_tags, {
    Name = "${local.prefix}-rds-sg01"
  })
}

resource "aws_security_group_rule" "tokyo_rds_from_saopaulo_mysql" {
  count = var.saopaulo_vpc_cidr == null ? 0 : 1

  type              = "ingress"
  security_group_id = aws_security_group.megatron_rds_sg01.id
  from_port         = 3306
  to_port           = 3306
  protocol          = "tcp"
  cidr_blocks       = [var.saopaulo_vpc_cidr]
  description       = "Allow MySQL from Sao Paulo VPC for Lab 3A"
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

resource "aws_db_subnet_group" "megatron_rds_subnet_group01" {
  name       = "${local.name_prefix}-rds-subnet-group01"
  subnet_ids = aws_subnet.megatron_private_subnets[*].id

  lifecycle {
    create_before_destroy = true
  }

  tags = {
    Name = "${local.name_prefix}-rds-subnet-group01"
  }
}

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

  tags = {
    Name = "${local.name_prefix}-rds01"
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

# ----------------------------------------
# Tokyo TGW
# ----------------------------------------
resource "aws_ec2_transit_gateway" "tokyo_tgw01" {
  description                     = "Tokyo TGW for Lab 3A"
  amazon_side_asn                 = 64512
  default_route_table_association = "disable"
  default_route_table_propagation = "disable"
  dns_support                     = "enable"
  vpn_ecmp_support                = "enable"

  tags = merge(local.common_tags, {
    Name = "${local.prefix}-tgw01"
  })
}

resource "aws_ec2_transit_gateway_route_table" "tokyo_tgw_rt01" {
  transit_gateway_id = aws_ec2_transit_gateway.tokyo_tgw01.id

  tags = merge(local.common_tags, {
    Name = "${local.prefix}-tgw-rt01"
  })
}

# ----------------------------------------
# Attach existing Tokyo VPC from Lab 2
# ----------------------------------------
resource "aws_ec2_transit_gateway_vpc_attachment" "tokyo_vpc_attach01" {
  transit_gateway_id = aws_ec2_transit_gateway.tokyo_tgw01.id
  vpc_id             = aws_vpc.megatron_vpc01.id
  subnet_ids         = aws_subnet.megatron_private_subnets[*].id

  dns_support = "enable"

  tags = merge(local.common_tags, {
    Name = "${local.prefix}-vpc-attach01"
  })
}

resource "aws_ec2_transit_gateway_route_table_association" "tokyo_assoc01" {
  transit_gateway_attachment_id  = aws_ec2_transit_gateway_vpc_attachment.tokyo_vpc_attach01.id
  transit_gateway_route_table_id = aws_ec2_transit_gateway_route_table.tokyo_tgw_rt01.id
}

resource "aws_ec2_transit_gateway_route_table_propagation" "tokyo_prop01" {
  transit_gateway_attachment_id  = aws_ec2_transit_gateway_vpc_attachment.tokyo_vpc_attach01.id
  transit_gateway_route_table_id = aws_ec2_transit_gateway_route_table.tokyo_tgw_rt01.id
}

# ----------------------------------------
# Phase 2: create inter-Region peering request
# Re-apply Tokyo after Sao Paulo TGW exists
# ----------------------------------------
resource "aws_ec2_transit_gateway_peering_attachment" "tokyo_to_saopaulo01" {
  count = var.saopaulo_tgw_id == null ? 0 : 1

  transit_gateway_id      = aws_ec2_transit_gateway.tokyo_tgw01.id
  peer_transit_gateway_id = var.saopaulo_tgw_id
  peer_region             = var.saopaulo_region

  tags = merge(local.common_tags, {
    Name = "${local.prefix}-to-liberdade-peer01"
  })
}

# Static TGW route to Sao Paulo VPC CIDR via peering
resource "aws_ec2_transit_gateway_route" "tokyo_to_saopaulo_cidr" {
  count = var.saopaulo_tgw_id != null && var.saopaulo_vpc_cidr != null ? 1 : 0

  destination_cidr_block         = var.saopaulo_vpc_cidr
  transit_gateway_route_table_id = aws_ec2_transit_gateway_route_table.tokyo_tgw_rt01.id
  transit_gateway_attachment_id  = aws_ec2_transit_gateway_peering_attachment.tokyo_to_saopaulo01[0].id
}

# Return routes in Tokyo private route tables
resource "aws_route" "tokyo_private_to_saopaulo" {
  count = var.saopaulo_vpc_cidr == null ? 0 : 1

  route_table_id         = aws_route_table.megatron_private_rt01.id
  destination_cidr_block = var.saopaulo_vpc_cidr
  transit_gateway_id     = aws_ec2_transit_gateway.tokyo_tgw01.id
}

