variable "aws_region" {
  description = "Region triển khai hạ tầng"
  type        = string
  default     = "us-east-1"
}

variable "project_name" {
  description = "Tên tiền tố cho các tài nguyên"
  type        = string
  default     = "demo-app"
}

variable "vpc_cidr" {
  description = "Dải IP cho VPC"
  type        = string
  default     = "10.0.0.0/16"
}

variable "instance_type" {
  description = "Loại máy chủ EC2"
  type        = string
  default     = "t2.micro"
}