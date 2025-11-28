variable "aws_region" {
  description = "AWS region for SES"
  type        = string
  default     = "ap-northeast-1"
}

variable "ses_domain" {
  description = "Domain to use with Amazon SES (Cloudflare で DNS 管理しているドメイン)"
  default     = "mail.small-engineer.net"
  type        = string
}
