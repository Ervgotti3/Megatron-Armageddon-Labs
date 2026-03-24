output "audit_logs_bucket_name" {
  value = aws_s3_bucket.audit_logs.id
}

output "cloudtrail_name" {
  value = aws_cloudtrail.global_trail.name
}

output "cloudtrail_arn" {
  value = aws_cloudtrail.global_trail.arn
}

output "app_fqdn" {
  value = "${var.app_subdomain}.${var.domain_name}"
}

output "cloudfront_domain_name" {
  value = aws_cloudfront_distribution.app.domain_name
}

output "acm_certificate_arn" {
  value = aws_acm_certificate.app_cert.arn
}

output "waf_web_acl_arn" {
  value = aws_wafv2_web_acl.cloudfront_acl.arn
}

output "waf_logs_bucket_name" {
  value = aws_s3_bucket.waf_logs.id
}