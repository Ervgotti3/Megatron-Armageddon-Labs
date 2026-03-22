output "tokyo_tgw_id" {
  value = aws_ec2_transit_gateway.tokyo_tgw01.id
}

output "tokyo_tgw_route_table_id" {
  value = aws_ec2_transit_gateway_route_table.tokyo_tgw_rt01.id
}

output "tokyo_vpc_id" {
  value = aws_vpc.megatron_vpc01.id
}

output "tokyo_vpc_cidr" {
  value = aws_vpc.megatron_vpc01.cidr_block
}

output "tokyo_rds_endpoint" {
  value = aws_db_instance.megatron_rds01.address
}

output "tokyo_to_saopaulo_peering_attachment_id" {
  value = try(aws_ec2_transit_gateway_peering_attachment.tokyo_to_saopaulo01[0].id, null)
}