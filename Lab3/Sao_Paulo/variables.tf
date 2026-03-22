variable "aws_region" {
  type    = string
  default = "sa-east-1"
}

variable "project_name" {
  description = "Prefix for naming."
  type        = string
  default     = "megatron-saopaulo"
}

variable "env" {
  description = "Environment name."
  type        = string
  default     = "lab3a"
}

variable "domain_name" {
  description = "Root domain name for the app."
  type        = string
  default     = "technology4gold.com"
}

variable "app_subdomain" {
  description = "Subdomain for the app."
  type        = string
  default     = "app"
}

variable "vpc_cidr" {
  description = "Sao Paulo VPC CIDR."
  type        = string
  default     = "10.88.0.0/16"
}

variable "public_subnet_cidrs" {
  description = "Sao Paulo public subnet CIDRs."
  type        = list(string)
  default     = ["10.88.1.0/24", "10.88.2.0/24"] #Two public subnets for ALB in different AZs
}

variable "private_subnet_cidrs" {
  description = "Sao Paulo private subnet CIDRs."
  type        = list(string)
  default     = ["10.88.101.0/24", "10.88.102.0/24"] #Two private subnets for ASG in different AZs
}

variable "azs" {
  description = "Sao Paulo availability zones."
  type        = list(string)
  default     = ["sa-east-1a", "sa-east-1c"] # Sao Paulo AZs for better availability
}

variable "tokyo_state_bucket" {
  description = "S3 bucket containing Tokyo Terraform remote state."
  type        = string
  default     = "decepticons-lab3-tfstate-02-09-2026"
}

variable "tokyo_state_key" {
  description = "Tokyo Terraform state key."
  type        = string
  default     = "tokyo/terraform.tfstate"
}

variable "tokyo_state_region" {
  description = "Region of the S3 bucket that stores Tokyo remote state."
  type        = string
  default     = "us-east-1"
}

variable "ec2_ami_id" {
  description = "AMI ID for the EC2 app host."
  type        = string
  default     = "ami-0b636fa791bb0970c" # Amazon Linux 2 in sa-east-1
}

variable "ec2_instance_type" {
  description = "EC2 instance size for the app."
  type        = string
  default     = "t3.micro"
}

variable "enable_alb_access_logs" {
  description = "Enable ALB access logging to S3."
  type        = bool
  default     = true
  #default     = "megatron-alb-logs-bucket01" # TODO: student supplies unique bucket name

}

variable "alb_access_logs_prefix" {
  description = "Prefix for ALB access logs in the S3 bucket."
  type        = string
  default     = "alb-access-logs"
}