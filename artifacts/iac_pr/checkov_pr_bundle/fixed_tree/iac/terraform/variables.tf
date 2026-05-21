###############################################################################
# Variables
###############################################################################

variable "aws_region" {
  description = "AWS region to deploy resources"
  type        = string
  default     = "ap-southeast-1" # Singapore
}

variable "project_prefix" {
  description = "Prefix for all resource names"
  type        = string
  default     = "threat-demo"
}

# Random suffix để tránh trùng tên global resources (S3, etc.)
resource "random_id" "suffix" {
  byte_length = 4
}

variable "admin_cidr_blocks" {
  description = "Approved administrative CIDR blocks for management access"
  type        = list(string)
  default     = ["10.0.0.0/24"]
}
