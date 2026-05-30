terraform {
  backend "s3" {
    bucket  = "test-bk-tdinh"
    key     = "terraform.tfstate"
    region  = "us-east-1"
    encrypt = true
  }
}