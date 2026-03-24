data "terraform_remote_state" "saopaulo" {
  backend = "s3"

  config = {
    bucket = var.saopaulo_state_bucket
    key    = var.saopaulo_state_key
    region = var.saopaulo_state_region
  }
}