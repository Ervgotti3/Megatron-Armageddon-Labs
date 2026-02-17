provider "aws" {
  alias  = "user1"
  region = var.aws_region
}

# Required for Lab 2 Bonus-B: CloudFront and ACM in us-east-1
# Create a second provider alias for us-east-1 for CloudFront viewer cert must be in us-east-1
provider "aws" {
  alias  = "us_east1"
  region = "us-east-1"
}