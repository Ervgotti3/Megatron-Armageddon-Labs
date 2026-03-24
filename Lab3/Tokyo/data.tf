data "terraform_remote_state" "saopaulo" {
  backend = "s3"

  config = {
    bucket = "decepticons-lab3-tfstate-02-09-2026"
    key    = "saopaulo/terraform.tfstate"
    region = "us-east-1"
  }
}