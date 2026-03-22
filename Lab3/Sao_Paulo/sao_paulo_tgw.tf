locals {
  saopaulo_name = "liberdade"
}
# ----------------------------------------
# Sao Paulo TGW
# ----------------------------------------
resource "aws_ec2_transit_gateway" "saopaulo_tgw01" {
  description                     = "Sao Paulo TGW (spoke) - Lab 3A"
  amazon_side_asn                 = 64513
  default_route_table_association = "disable"
  default_route_table_propagation = "disable"
  dns_support                     = "enable"

  tags = {
    Name = "${local.saopaulo_name}-${local.name_prefix}-tgw01"
  }
}

resource "aws_ec2_transit_gateway_route_table" "saopaulo_tgw_rt01" {
  transit_gateway_id = aws_ec2_transit_gateway.saopaulo_tgw01.id

  tags = {
    Name = "${local.saopaulo_name}-${local.name_prefix}-tgw-rt01"
  }
}

# Attach existing Sao Paulo VPC from your Lab 2-minus-DB buildout to this TGW. This will be the "spoke" in our hub-and-spoke design. We will peer this TGW with the Tokyo TGW in Lab 3B, and then add routes to enable communication between the two regions in Lab 3C.

resource "aws_ec2_transit_gateway_vpc_attachment" "saopaulo_vpc_attach01" {
  transit_gateway_id = aws_ec2_transit_gateway.saopaulo_tgw01.id
  vpc_id             = aws_vpc.megatron_vpc01.id
  subnet_ids         = aws_subnet.megatron_private_subnets[*].id

  dns_support = "enable"

  tags = {
    Name = "${local.saopaulo_name}-${local.name_prefix}-vpc-attach01"
  }
}

resource "aws_ec2_transit_gateway_route_table_association" "saopaulo_assoc01" {
  transit_gateway_attachment_id  = aws_ec2_transit_gateway_vpc_attachment.saopaulo_vpc_attach01.id
  transit_gateway_route_table_id = aws_ec2_transit_gateway_route_table.saopaulo_tgw_rt01.id
}

resource "aws_ec2_transit_gateway_route_table_propagation" "saopaulo_prop01" {
  transit_gateway_attachment_id  = aws_ec2_transit_gateway_vpc_attachment.saopaulo_vpc_attach01.id
  transit_gateway_route_table_id = aws_ec2_transit_gateway_route_table.saopaulo_tgw_rt01.id
}

output "saopaulo_tgw_id" {
  value = aws_ec2_transit_gateway.saopaulo_tgw01.id
}