variable "aws_region" {
  description = "AWS Region for the megatron fleet to patrol."
  type        = string
  default     = "us-east-1"
}

variable "project_name" {
  description = "Prefix for naming. Student has changed the name from megatron to 'megatron'."
  type        = string
  default     = "megatron"
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

variable "app_bootstrap" {
  description = "User data script content to install and configure the application on the EC2 instance."
  type        = string
  default     = "yes"
}

variable "cw_bootstrap" {
  description = "User data script content to install and configure CloudWatch Agent on the EC2 instance."
  type        = string
  default     = "yes"
}

variable "certificate_validation_method" {
  description = "Method for validating the ACM certificate (DNS or EMAIL)."
  type        = string
  default     = "DNS"
}

variable "env" {
  description = "This is project will only be ran in the lab (test) env not production."
  default     = "lab1"
  type        = string
}

variable "alb_5xx_evaluation_periods" {
  description = "Number of periods to evaluate for ALB 5xx errors."
  type        = number
  default     = 2
}

variable "alb_5xx_threshold" {
  description = "Threshold for ALB 5xx errors to trigger alarm."
  type        = number
  default     = 1
}

variable "alb_5xx_period_seconds" {
  description = "Period in seconds for ALB 5xx error evaluation."
  type        = number
  default     = 60
}

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
  description = "Availability Zones list (match count with subnets)."
  type        = list(string)
  default     = ["us-east-1a", "us-east-1b"] # TODO: student supplies
}

variable "ec2_ami_id" {
  description = "AMI ID for the EC2 app host."
  type        = string
  default     = "ami-07ff62358b87c7116" # Amazon Linux 2 in us-east-1
}

variable "ec2_instance_type" {
  description = "EC2 instance size for the app."
  type        = string
  default     = "t3.micro"
}

variable "db_engine" {
  description = "RDS engine."
  type        = string
  default     = "mysql"
}

variable "db_instance_class" {
  description = "RDS instance class."
  type        = string
  default     = "db.t3.micro"
}

variable "db_name" {
  description = "Initial database name."
  type        = string
  default     = "Cybertronsqldb" # Students can change
}

variable "db_username" {
  description = "DB master username (students should use Secrets Manager in 1B/1C)."
  type        = string
  default     = "admin" # TODO: student supplies
}

variable "db_password" {
  description = "DB master password (DO NOT hardcode in real life; for lab only)."
  type        = string
  sensitive   = true
  default     = "AllhailMegatron123!" # TODO: student supplies
}

variable "sns_email_endpoint" {
  description = "Email for SNS subscription (PagerDuty simulation)."
  type        = string
  default     = "ervinjkershaw@gmail.com" # TODO: student supplies
}

variable "enable_alb_access_logs" {
  description = "Enable ALB access logging to S3."
  type        = bool
  default     = true
  #default     = "megatron-alb-logs-bucket01" # TODO: student supplies unique bucket name

}

variable "manage_route53_in_terraform" {
  description = "Whether to create and manage the Route53 hosted zone in Terraform."
  type        = bool
  default     = false
}

variable "route53_hosted_megatron_zone_id" {
  description = "Pre-existing Route53 hosted zone ID (if not managing in Terraform)."
  #description = "If manage_route53_in_terraform=false, provide existing Hosted Zone ID for domain."
  type    = string
  default = "Z08885424JO0XI2RFETE" # TODO: student supplies if not managing in Terraform
}

variable "alb_access_logs_prefix" {
  description = "Prefix for ALB access logs in the S3 bucket."
  type        = string
  default     = "alb-access-logs"
}

variable "enable_waf" {
  description = "Enable WAFv2 for the ALB"
  type        = bool
  default     = true
}

variable "waf_log_destination" {
  description = "Where WAF logs are sent: cloudwatch | s3 | firehose"
  type        = string
  default     = "cloudwatch"
}

variable "waf_log_retention_days" {
  description = "Number of days to retain WAF CloudWatch logs."
  type        = number
  default     = 14
}

variable "enable_waf_sampled_requests_only" {
  description = "If true, students can optionally filter/redact fields later. (Placeholder toggle.)"
  type        = bool
  default     = false
}
