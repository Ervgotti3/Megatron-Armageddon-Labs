variable "aws_region" {
  type    = string
  default = "us-east-1"
}

variable "project_name" {
  type    = string
  default = "megatron-global"
}

variable "env" {
  type    = string
  default = "lab3b"
}

variable "domain_name" {
  type    = string
  default = "technology4gold.com"
}

variable "app_subdomain" {
  type    = string
  default = "app"
}

variable "saopaulo_state_bucket" {
  type    = string
  default = "decepticons-lab3-tfstate-02-09-2026"
}

variable "saopaulo_state_key" {
  type    = string
  default = "saopaulo/terraform.tfstate"
}

variable "saopaulo_state_region" {
  type    = string
  default = "us-east-1"
}