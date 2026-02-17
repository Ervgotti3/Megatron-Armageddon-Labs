# CloudFront viewer cert must be in us-east-1
resource "aws_acm_certificate" "megatron_cf_cert01" {
  provider          = aws.us_east1
  domain_name       = var.domain_name
  validation_method = "DNS"

  subject_alternative_names = [
    "app.${var.domain_name}"
  ]

  lifecycle {
    create_before_destroy = true
  }

  tags = {
    Name = "${var.project_name}-cf-cert01"
  }
}

resource "aws_route53_record" "megatron_cf_cert_validation_records01" {
  allow_overwrite = true # In case of cert re-creation, Route53 records will be updated instead of causing a conflict.

  for_each = {
    for dvo in aws_acm_certificate.megatron_cf_cert01.domain_validation_options :
    dvo.domain_name => {
      name  = dvo.resource_record_name
      type  = dvo.resource_record_type
      value = dvo.resource_record_value
    }
  }

  zone_id = local.megatron_zone_id
  name    = each.value.name
  type    = each.value.type
  ttl     = 60
  records = [each.value.value]
}

resource "aws_acm_certificate_validation" "megatron_cf_cert_validation01" {
  provider                = aws.us_east1
  certificate_arn         = aws_acm_certificate.megatron_cf_cert01.arn
  validation_record_fqdns = [for r in aws_route53_record.megatron_cf_cert_validation_records01 : r.fqdn]
}
