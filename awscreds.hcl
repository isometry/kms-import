log_level = "error"

vault {
  address = "https://vault.breathe.io"
}

secret {
  format    = "AWS_{{ key | replaceKey `access_key` `ACCESS_KEY_ID` | replaceKey `secret_key` `SECRET_ACCESS_KEY` | replaceKey `security_token` `SESSION_TOKEN` }}"
  no_prefix = true
  path      = "aws/sts/limited-admin"
}

upcase = true

exec {
  env {
    denylist = [
      "AWS_ARN",
    ]
  }
}

