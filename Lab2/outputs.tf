# Explanation: Outputs are your mission report—what got built and where to find it.
output "megatron_vpc_id" {
  value = aws_vpc.megatron_vpc01.id
}

output "megatron_public_subnet_ids" {
  value = aws_subnet.megatron_public_subnets[*].id
}

output "megatron_private_subnet_ids" {
  value = aws_subnet.megatron_private_subnets[*].id
}

output "megatron_ec2_instance_id" {
  value = aws_instance.megatron_ec2_01.id
}

output "megatron_rds_endpoint" {
  value = aws_db_instance.megatron_rds01.address
}

output "megatron_sns_topic_arn" {
  value = aws_sns_topic.megatron_sns_topic01.arn
}

output "megatron_log_group_name" {
  value = length(aws_cloudwatch_log_group.megatron_log_group01) > 0 ? aws_cloudwatch_log_group.megatron_log_group01[0].name : null
}

# Explanation: These outputs prove megatron built private hyperspace lanes (endpoints) instead of public chaos.
output "megatron_vpce_ssm_id" {
  value = aws_vpc_endpoint.megatron_vpce_ssm01.id
}

output "megatron_vpce_logs_id" {
  value = aws_vpc_endpoint.megatron_vpce_logs01.id
}

output "megatron_vpce_secrets_id" {
  value = aws_vpc_endpoint.megatron_vpce_secrets01.id
}

output "megatron_vpce_s3_id" {
  value = aws_vpc_endpoint.megatron_vpce_s3_gw01.id
}

output "megatron_private_ec2_instance_id_bonus" {
  value = aws_instance.megatron_ec2_01.id
}

#Bonus-B outputs (append to outputs.tf)
# Explanation: Outputs are the mission coordinates — where to point your browser and your blasters.
output "megatron_alb_dns_name" {
  value = aws_lb.megatron_alb01.dns_name
}

output "megatron_app_fqdn" {
  value = "${var.app_subdomain}.${var.domain_name}"
}

output "megatron_target_group_arn" {
  value = aws_lb_target_group.megatron_tg01.arn
}

output "megatron_acm_cert_arn" {
  value = aws_acm_certificate.megatron_acm_cert01.arn
}


output "megatron_dashboard_name" {
  value = aws_cloudwatch_dashboard.megatron_dashboard01.dashboard_name
}

output "megatron_route53_zone_id" {
  #value = var.manage_route53_in_terraform ? aws_route53_zone.megatron_zone01.zone_id : var.route53_hosted_megatron_zone_id
  #value = var.manage_route53_in_terraform ? aws_route53_zone.megatron_zone01[0].zone_id : var.route53_hosted_megatron_zone_id
  #value = var.manage_route53_in_terraform ? try(one(aws_route53_zone.megatron_zone01[*].zone_id), null) : (var.route53_hosted_megatron_zone_id != "" ? var.route53_hosted_megatron_zone_id : null)
  value = local.megatron_zone_id
}

output "megatron_app_url_https" {
  value = "https://${var.app_subdomain}.${var.domain_name}"
}

output "megatron_alb_logs_bucket_name" {
  value = var.enable_alb_access_logs ? aws_s3_bucket.megatron_alb_logs_bucket01[0].bucket : null
}

output "megatron_waf_log_destination" {
  value = local.waf_log_destination
}

output "megatron_waf_arn" {
  value = var.enable_waf ? aws_wafv2_web_acl.megatron_cf_waf01[0].arn : null
}

output "megatron_waf_cw_log_group_name" {
  #value = var.enable_waf && var.waf_log_destination == "cloudwatch" ? aws_cloudwatch_log_group.megatron_cf_waf_log_group01[0].name : nulldepends_on = [  ]
  value = var.waf_log_destination == "s3" ? aws_s3_bucket.megatron_waf_logs_bucket01[0].bucket : null
}

output "megatron_waf_logs_s3_bucket_name" {
  value = var.waf_log_destination == "s3" ? aws_s3_bucket.megatron_waf_logs_bucket01[0].bucket : null
}

output "megatron_waf_firehose_name" {
  value = var.waf_log_destination == "firehose" ? aws_kinesis_firehose_delivery_stream.megatron_waf_firehose01[0].name : null
}