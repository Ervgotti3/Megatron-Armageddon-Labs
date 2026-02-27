#####################################################################
# Lab 2B-Honors+ - Optional invalidation action (run on demand)
#####################################################################
# Part C provides two options:
#   Option 1 (Recommended): Keep invalidations as manual runbook ops
#   Option 2 (Advanced/Optional): Terraform invalidation action


# Explanation: This is Megatron’s “break glass” lever — use it sparingly or the bill will bite.
resource "aws_cloudfront_create_invalidation" "megatron_invalidate_index01" {
  distribution_id = aws_cloudfront_distribution.megatron_cf01.id

  # TODO: students must pick the smallest path set that fixes the issue.
  paths = [
    "/static/index.html"
  ]
}

