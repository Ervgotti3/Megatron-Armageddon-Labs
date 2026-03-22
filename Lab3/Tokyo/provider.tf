provider "aws" {
  region = var.aws_region
}

data "aws_region" "megatron_region01" {}

data "aws_caller_identity" "megatron_self01" {}