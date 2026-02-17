# Explanation: The shield generator moves to the edge — CloudFront WAF blocks nonsense before it hits your VPC.
resource "aws_wafv2_web_acl" "megatron_cf_waf01" {
  count = var.enable_waf ? 1 : 0
  name  = "${var.project_name}-cf-waf01"
  scope = "CLOUDFRONT" # Lab 2 requirement: WAF moves from ALB (REGIONAL) → CloudFront (CLOUDFRONT)

  default_action {
    allow {}
  }

  visibility_config {
    cloudwatch_metrics_enabled = true
    metric_name                = "${var.project_name}-waf01"
    sampled_requests_enabled   = true
  }

  # Explanation: AWS managed rules are like hiring Rebel commandos — they’ve seen every trick.
  rule {
    name     = "AWSManagedRulesCommonRuleSet"
    priority = 1

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
      metric_name                = "${var.project_name}-cf-waf-common"
      sampled_requests_enabled   = true
    }
  }

  tags = {
    Name = "${var.project_name}-cf-waf01"
  }
}