locals {
  prefix     = var.project_name
  env        = var.env
  fqdn       = "${var.app_subdomain}.${var.domain_name}"
  account_id = data.aws_caller_identity.current.account_id

  audit_bucket_name    = lower("${local.prefix}-${local.env}-${local.account_id}-audit-logs")
  trail_name           = "${local.prefix}-${local.env}-trail"
  waf_logs_bucket_name = "aws-waf-logs-${lower(var.project_name)}-${lower(var.env)}-${data.aws_caller_identity.current.account_id}"
}

# Create S3 bucket for CloudTrail logs with appropriate security settings
resource "aws_s3_bucket" "audit_logs" {
  bucket = local.audit_bucket_name

  tags = {
    Name      = local.audit_bucket_name
    ManagedBy = "terraform"
    Project   = "lab-3b-global-controls"
    FQDN      = local.fqdn
  }
}

resource "aws_s3_bucket_versioning" "audit_logs" {
  bucket = aws_s3_bucket.audit_logs.id

  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "audit_logs" {
  bucket = aws_s3_bucket.audit_logs.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_s3_bucket_public_access_block" "audit_logs" {
  bucket = aws_s3_bucket.audit_logs.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_ownership_controls" "audit_logs" {
  bucket = aws_s3_bucket.audit_logs.id

  rule {
    object_ownership = "BucketOwnerPreferred"
  }
}

resource "aws_s3_bucket_acl" "audit_logs" {
  depends_on = [aws_s3_bucket_ownership_controls.audit_logs]
  bucket     = aws_s3_bucket.audit_logs.id
  acl        = "private"
}

data "aws_iam_policy_document" "cloudtrail_bucket_policy" {
  statement {
    sid = "AWSCloudTrailAclCheck"

    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com"]
    }

    actions   = ["s3:GetBucketAcl"]
    resources = [aws_s3_bucket.audit_logs.arn]

    condition {
      test     = "StringEquals"
      variable = "aws:SourceArn"
      values   = ["arn:aws:cloudtrail:${var.aws_region}:${local.account_id}:trail/${local.trail_name}"]
    }
  }

  statement {
    sid = "AWSCloudTrailWrite"

    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com"]
    }

    actions = ["s3:PutObject"]
    resources = [
      "${aws_s3_bucket.audit_logs.arn}/AWSLogs/${local.account_id}/*"
    ]

    condition {
      test     = "StringEquals"
      variable = "s3:x-amz-acl"
      values   = ["bucket-owner-full-control"]
    }

    condition {
      test     = "StringEquals"
      variable = "aws:SourceArn"
      values   = ["arn:aws:cloudtrail:${var.aws_region}:${local.account_id}:trail/${local.trail_name}"]
    }
  }
}

resource "aws_s3_bucket_policy" "audit_logs" {
  bucket = aws_s3_bucket.audit_logs.id
  policy = data.aws_iam_policy_document.cloudtrail_bucket_policy.json
}

resource "aws_cloudtrail" "global_trail" {
  name                          = local.trail_name
  s3_bucket_name                = aws_s3_bucket.audit_logs.id
  include_global_service_events = true
  is_multi_region_trail         = true
  enable_log_file_validation    = true

  depends_on = [aws_s3_bucket_policy.audit_logs]
}

# Global edge distribution for the app in Sao Paulo
data "aws_route53_zone" "primary" {
  name         = var.domain_name
  private_zone = false
}

resource "aws_acm_certificate" "app_cert" {
  domain_name       = "${var.app_subdomain}.${var.domain_name}"
  validation_method = "DNS"

  lifecycle {
    create_before_destroy = true
  }

  tags = {
    Name      = "${var.app_subdomain}.${var.domain_name}"
    ManagedBy = "terraform"
    Project   = "lab-3b-global-controls"
  }
}

resource "aws_route53_record" "app_cert_validation" {
  for_each = {
    for dvo in aws_acm_certificate.app_cert.domain_validation_options : dvo.domain_name => {
      name   = dvo.resource_record_name
      type   = dvo.resource_record_type
      record = dvo.resource_record_value
    }
  }

  zone_id = data.aws_route53_zone.primary.zone_id
  name    = each.value.name
  type    = each.value.type
  ttl     = 60
  records = [each.value.record]
}

resource "aws_acm_certificate_validation" "app_cert" {
  certificate_arn         = aws_acm_certificate.app_cert.arn
  validation_record_fqdns = [for r in aws_route53_record.app_cert_validation : r.fqdn]
}

resource "aws_cloudfront_distribution" "app" {
  enabled             = true
  is_ipv6_enabled     = true
  comment             = "Lab 3B global edge for ${var.app_subdomain}.${var.domain_name}"
  default_root_object = ""
  web_acl_id          = aws_wafv2_web_acl.cloudfront_acl.arn
  aliases             = ["${var.app_subdomain}.${var.domain_name}"]

  origin {
    domain_name = data.terraform_remote_state.saopaulo.outputs.saopaulo_alb_dns_name
    origin_id   = "saopaulo-alb"

    custom_origin_config {
      http_port              = 80
      https_port             = 443
      origin_protocol_policy = "http-only"
      origin_ssl_protocols   = ["TLSv1.2"]
    }
  }

  default_cache_behavior {
    target_origin_id       = "saopaulo-alb"
    viewer_protocol_policy = "redirect-to-https"
    allowed_methods        = ["GET", "HEAD", "OPTIONS", "PUT", "POST", "PATCH", "DELETE"]
    cached_methods         = ["GET", "HEAD", "OPTIONS"]
    compress               = true

    forwarded_values {
      query_string = true

      cookies {
        forward = "all"
      }

      headers = ["*"]
    }
  }

  restrictions {
    geo_restriction {
      restriction_type = "none"
    }
  }

  viewer_certificate {
    acm_certificate_arn      = aws_acm_certificate_validation.app_cert.certificate_arn
    ssl_support_method       = "sni-only"
    minimum_protocol_version = "TLSv1.2_2021"
  }

  depends_on = [aws_acm_certificate_validation.app_cert]

  tags = {
    Name      = "${var.project_name}-${var.env}-cloudfront"
    ManagedBy = "terraform"
    Project   = "lab-3b-global-controls"
  }
}

resource "aws_route53_record" "app_alias" {
  zone_id = data.aws_route53_zone.primary.zone_id
  name    = "${var.app_subdomain}.${var.domain_name}"
  type    = "A"

  alias {
    name                   = aws_cloudfront_distribution.app.domain_name
    zone_id                = aws_cloudfront_distribution.app.hosted_zone_id
    evaluate_target_health = false
  }
}

# WAFv2 Web ACL for CloudFront with AWS Managed Rules and logging to S3
resource "aws_s3_bucket" "waf_logs" {
  bucket = local.waf_logs_bucket_name

  tags = {
    Name      = local.waf_logs_bucket_name
    ManagedBy = "terraform"
    Project   = "lab-3b-global-controls"
  }
}

resource "aws_s3_bucket_versioning" "waf_logs" {
  bucket = aws_s3_bucket.waf_logs.id

  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "waf_logs" {
  bucket = aws_s3_bucket.waf_logs.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_s3_bucket_public_access_block" "waf_logs" {
  bucket = aws_s3_bucket.waf_logs.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_wafv2_web_acl" "cloudfront_acl" {
  name  = "${var.project_name}-${var.env}-cloudfront-acl"
  scope = "CLOUDFRONT"

  default_action {
    allow {}
  }

  rule {
    name     = "AWSManagedRulesCommonRuleSet"
    priority = 10

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
      metric_name                = "AWSManagedRulesCommonRuleSet"
      sampled_requests_enabled   = true
    }
  }

  visibility_config {
    cloudwatch_metrics_enabled = true
    metric_name                = "${var.project_name}-${var.env}-cloudfront-acl"
    sampled_requests_enabled   = true
  }

  tags = {
    Name      = "${var.project_name}-${var.env}-cloudfront-acl"
    ManagedBy = "terraform"
    Project   = "lab-3b-global-controls"
  }
}

resource "aws_wafv2_web_acl_logging_configuration" "cloudfront_acl" {
  resource_arn            = aws_wafv2_web_acl.cloudfront_acl.arn
  log_destination_configs = [aws_s3_bucket.waf_logs.arn]
}