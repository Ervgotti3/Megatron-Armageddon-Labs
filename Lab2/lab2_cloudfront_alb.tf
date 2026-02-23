# Explanation: CloudFront is the only public doorway — Chewbacca stands behind it with private infrastructure.
resource "aws_cloudfront_distribution" "megatron_cf01" {
  enabled         = true
  is_ipv6_enabled = true
  comment         = "${var.project_name}-cf01"

  origin {
    origin_id   = "${var.project_name}-alb-origin01"
    domain_name = aws_lb.megatron_alb01.dns_name

    custom_origin_config {
      http_port              = 80
      https_port             = 443
      origin_protocol_policy = "https-only"
      origin_ssl_protocols   = ["TLSv1.2"]
    }

    # Explanation: CloudFront whispers the secret growl — the ALB only trusts this.
    custom_header {
      name  = "X-Megatron-Growl"
      value = random_password.megatron_origin_header_value01.result
    }
  }

  ################################################################################################
  # Lab 2B-Honors - A) /api/public-feed = origin-driven caching
  ################################################################################################

  # Explanation: Public feed is cacheable—but only if the origin explicitly says so. Megatron demands consent.
  ordered_cache_behavior {
    path_pattern           = "/api/public-feed"
    target_origin_id       = "${var.project_name}-alb-origin01"
    viewer_protocol_policy = "redirect-to-https"

    allowed_methods = ["GET", "HEAD", "OPTIONS"]
    cached_methods  = ["GET", "HEAD"]

    # Honor Cache-Control from origin (and default to not caching without it). :contentReference[oaicite:8]{index=8}
    cache_policy_id = data.aws_cloudfront_cache_policy.megatron_use_origin_cache_headers01.id

    # Forward what origin needs. Keep it tight: don't forward everything unless required. :contentReference[oaicite:9]{index=9}
    origin_request_policy_id = data.aws_cloudfront_origin_request_policy.megatron_orp_all_viewer_except_host01.id
  }


  #################################################################################################
  # Lab 2B-Honors - B) /api/* = still safe default (no caching)
  #################################################################################################  

  # Explanation: Everything else under /api is dangerous by default—Megatron disables caching until proven safe.

  default_cache_behavior {
    target_origin_id       = "${var.project_name}-alb-origin01"
    viewer_protocol_policy = "redirect-to-https"

    allowed_methods = ["GET", "HEAD", "OPTIONS", "PUT", "POST", "PATCH", "DELETE"]
    cached_methods  = ["GET", "HEAD"]

    cache_policy_id          = aws_cloudfront_cache_policy.megatron_cache_api_disabled01.id
    origin_request_policy_id = aws_cloudfront_origin_request_policy.megatron_orp_api01.id
  }

  # Explanation: Static behavior is the speed lane—megatron caches it hard for performance.
  ordered_cache_behavior {
    path_pattern           = "/static/*"
    target_origin_id       = "${var.project_name}-alb-origin01"
    viewer_protocol_policy = "redirect-to-https"

    allowed_methods = ["GET", "HEAD", "OPTIONS"]
    cached_methods  = ["GET", "HEAD"]

    cache_policy_id            = aws_cloudfront_cache_policy.megatron_cache_static01.id
    origin_request_policy_id   = aws_cloudfront_origin_request_policy.megatron_orp_static01.id
    response_headers_policy_id = aws_cloudfront_response_headers_policy.megatron_rsp_static01.id
  }

  # Explanation: Attach WAF at the edge — now WAF moved to CloudFront.
  #web_acl_id = aws_wafv2_web_acl.megatron_cf_waf01[0].arn
  ## use this so you don’t crash when enable_waf = false:
  web_acl_id = var.enable_waf ? aws_wafv2_web_acl.megatron_cf_waf01[0].arn : null


  # TODO: students set aliases for technology4gold.com and app.technology4gold.com
  aliases = [
    var.domain_name,
    "${var.app_subdomain}.${var.domain_name}"
  ]

  # TODO: students must use ACM cert in us-east-1 for CloudFront
  viewer_certificate {
    acm_certificate_arn      = aws_acm_certificate_validation.megatron_cf_cert_validation01.certificate_arn
    ssl_support_method       = "sni-only"
    minimum_protocol_version = "TLSv1.2_2021"
  }

  restrictions {
    geo_restriction {
      restriction_type = "none"
    }
  }
}

#no longer needed since we moved WAF to CloudFront in Lab2
#You’ll need this variable:
#variable "cloudfront_acm_cert_arn" {
#  description = "ACM certificate ARN in us-east-1 for CloudFront (covers technology4gold.com and app.technology4gold.com)."
#  type        = string
#  default     = null
#}


