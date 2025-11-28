output "sses_verification_txt_record" {
  description = "SES domain verification TXT record to create in Cloudflare"
  value = {
    name = "_amazonses.${aws_ses_domain_identity.this.domain}"
    type = "TXT"
    value = aws_ses_domain_identity.this.verification_token
  }
}

output "ses_dkim_cname_records" {
  description = "SES DKIM CNAME records to create in Cloudflare"
  value = [
    for t in aws_ses_domain_dkim.this.dkim_tokens : {
      name  = "${t}._domainkey.${aws_ses_domain_identity.this.domain}"
      type  = "CNAME"
      value = "${t}.dkim.amazonses.com"
    }
  ]
}

output "ses_spf_txt_record" {
  description = "Recommended SPF TXT record value for Cloudflare"
  value = {
    name  = aws_ses_domain_identity.this.domain
    type  = "TXT"
    value = "v=spf1 include:amazonses.com ~all"
  }
}
