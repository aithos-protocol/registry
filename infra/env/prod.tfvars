environment      = "prod"
hostname         = "registry.aithos.world"
parent_zone_name = "aithos.world"

# The organization's service control policy allows only us-east-1 and
# us-west-1. Decision of 2026-08-31: production launches in us-east-1 — the
# same region the CloudFront certificate must live in anyway, and the same as
# development, so nothing about the stack changes shape. The European question
# is commercial, not technical, and stays open: answering it later means
# amending the SCP and standing up a new environment, never editing this one.
region = "us-east-1"

# Publishing is rare by nature. Development runs the permissive default (100);
# production has no migration traffic and no excuse: 20 writes per address per
# five minutes inconveniences nobody real and divides the worst-case daily S3
# cost of one abusive address by five. Audit recommendation, 27/08 and 29/08.
write_rate_limit = 20

# alarm_email is deliberately absent from this file — a committed address
# would mean anyone who forks and applies this sends their alarms to whoever
# wrote it. Pass it at apply time; for environment = "prod" the variable
# validation makes forgetting it an error instead of a silent nobody-reads-it:
#
#   terraform apply -var-file=env/prod.tfvars -var alarm_email=you@example.com
