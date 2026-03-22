variable "aws_region" {
  type    = string
  default = "ap-northeast-1"
}

variable "project_name" {
  description = "Prefix for naming. Student has changed the name from megatron to 'megatron'."
  type        = string
  default     = "megatron"
}

variable "env" {
  description = "This is project will only be ran in the lab (test) env not production."
  default     = "lab3a"
  type        = string
}

variable "domain_name" {
  description = "Root domain name for the app (e.g., example.com)."
  type        = string
  default     = "technology4gold.com" # TODO: student supplies domain name

}
variable "app_subdomain" {
  description = "Subdomain for the app (e.g., technology4gold.com -> 'app')."
  type        = string
  default     = "app" # TODO: student supplies subdomain
}

#
variable "vpc_cidr" {
  description = "VPC CIDR (use 10.x.x.x/xx as instructed)."
  type        = string
  default     = "10.77.0.0/16" # TODO: student supplies
}

variable "public_subnet_cidrs" {
  description = "Public subnet CIDRs (use 10.x.x.x/xx)."
  type        = list(string)
  default     = ["10.77.1.0/24", "10.77.2.0/24"] # TODO: student supplies
}

variable "private_subnet_cidrs" {
  description = "Private subnet CIDRs (use 10.x.x.x/xx)."
  type        = list(string)
  default     = ["10.77.101.0/24", "10.77.102.0/24"] # TODO: student supplies
}

variable "azs" {
  description = "Availability zones for subnets (e.g., [\"ap-northeast-1a\", \"ap-northeast-1c\"])."
  type        = list(string)
  default     = ["ap-northeast-1a", "ap-northeast-1c"] # TODO: student supplies
}

variable "db_engine" {
  type    = string
  default = "mysql"
}

variable "db_instance_class" {
  type    = string
  default = "db.t3.micro"
}

variable "db_name" {
  type    = string
  default = "appdb"
}

variable "db_username" {
  type    = string
  default = "admin"
}

variable "db_password" {
  type      = string
  sensitive = true
  default   = "megatron123"
}

# Variables for Sao Paulo TGW attachment and peering
# Populated in Tokyo phase 2
variable "saopaulo_tgw_id" {
  description = "São Paulo TGW ID, used by Tokyo to create TGW peering."
  type        = string
  default     = null
}

variable "saopaulo_vpc_cidr" {
  description = "São Paulo VPC CIDR, used by Tokyo to create routes and RDS SG rule."
  type        = string
  default     = null
}

# Populated from Sao Paulo remote state
variable "saopaulo_region" {
  description = "São Paulo AWS region."
  type        = string
  default     = "sa-east-1"
}

