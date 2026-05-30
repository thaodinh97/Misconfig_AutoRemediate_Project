output "server_public_ip" {
  description = "Địa chỉ Public IP của EC2 Server"
  value       = aws_instance.web.public_ip
}

output "vpc_id" {
  description = "ID của VPC"
  value       = aws_vpc.main.id
}