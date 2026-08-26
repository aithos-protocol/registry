environment      = "dev"
hostname         = "registry-dev.aithos.world"
parent_zone_name = "aithos.world"

# The organization's service control policy allows only us-east-1 and
# us-west-1. us-east-1 is chosen because CloudFront requires its certificate
# there regardless, so the whole stack sits in one region.
#
# The production region is a separate decision: it is the one where the
# positioning argument for Europe has weight, and it needs the SCP question
# answered deliberately rather than worked around.
region = "us-east-1"
