####################################################################################
# Lab 2B-Honors - Origin Driven Caching (Managed Policies)
####################################################################################

# Explanation: Megatron uses AWS-managed policies—battle-tested configs so students learn the real names.
data "aws_cloudfront_cache_policy" "megatron_use_origin_cache_headers01" {
  name = "UseOriginCacheControlHeaders"
}

# Explanation: Same idea, but includes query strings in the cache key when your API truly varies by them.
data "aws_cloudfront_cache_policy" "megatron_use_origin_cache_headers_qs01" {
  name = "UseOriginCacheControlHeaders-QueryStrings"
}

## Explanation: Origin request policies let us forward needed stuff without polluting the cache key.
## (Origin request policies are separate from cache policies.) :contentReference[oaicite:6]{index=6}
#data "aws_cloudfront_origin_request_policy" "megatron_orp_all_viewer01" {
#  name = "Managed-AllViewer"
#}

data "aws_cloudfront_origin_request_policy" "megatron_orp_all_viewer_except_host01" {
  name = "Managed-AllViewerExceptHostHeader"
}







