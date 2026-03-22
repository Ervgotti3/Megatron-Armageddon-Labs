terraform {
  required_version = ">= 1.5"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 5.0"
    }
  }

  backend "s3" {
    bucket  = "decepticons-lab3-tfstate-02-09-2026" # you create once
    key     = "saopaulo/terraform.tfstate"
    region  = "us-east-1"
    encrypt = true
  }
}