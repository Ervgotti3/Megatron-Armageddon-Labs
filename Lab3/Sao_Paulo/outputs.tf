output "saopaulo_tgw_id" {
  value = aws_ec2_transit_gateway.saopaulo_tgw01.id
}

output "saopaulo_vpc_cidr" {
  value = aws_vpc.megatron_vpc01.cidr_block
}

output "saopaulo_region" {
  value = var.aws_region
}

output "saopaulo_alb_dns_name" {
  value = aws_lb.megatron_alb01.dns_name
}

output "saopaulo_alb_zone_id" {
  value = aws_lb.megatron_alb01.zone_id
}