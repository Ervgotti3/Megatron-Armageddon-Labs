# ----------------------------------------
# Phase 2: accept Tokyo peering request
# ----------------------------------------

locals {
  tokyo_peer_attachment_id = try(
    data.terraform_remote_state.tokyo.outputs.tokyo_to_saopaulo_peering_attachment_id,
    null
  )
}

# Accept peering request created in Tokyo
resource "aws_ec2_transit_gateway_peering_attachment_accepter" "saopaulo_peer_accept01" {
  count = local.tokyo_peer_attachment_id == null ? 0 : 1

  transit_gateway_attachment_id = local.tokyo_peer_attachment_id

  tags = merge(local.common_tags, {
    Name = "${local.prefix}-peer-accept01"
  })
}

# Static TGW route to Tokyo CIDR via peering
resource "aws_ec2_transit_gateway_route" "saopaulo_to_tokyo_cidr" {
  count = local.tokyo_peer_attachment_id == null ? 0 : 1

  destination_cidr_block         = data.terraform_remote_state.tokyo.outputs.tokyo_vpc_cidr
  transit_gateway_route_table_id = aws_ec2_transit_gateway_route_table.saopaulo_tgw_rt01.id
  transit_gateway_attachment_id  = aws_ec2_transit_gateway_peering_attachment_accepter.saopaulo_peer_accept01[0].id
}

# VPC private route table -> Tokyo CIDR via TGW
resource "aws_route" "saopaulo_private_to_tokyo" {
  count = local.tokyo_peer_attachment_id == null ? 0 : 1

  route_table_id         = aws_route_table.megatron_private_rt01.id
  destination_cidr_block = data.terraform_remote_state.tokyo.outputs.tokyo_vpc_cidr
  transit_gateway_id     = aws_ec2_transit_gateway.saopaulo_tgw01.id
}