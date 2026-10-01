# Experimental observation profile. This is not an independent transparency log.
variable "experimental_trust_enabled" {
  type        = bool
  default     = false
  description = "Enable short-lived PR117 domain and hosted-management observations."
}
resource "aws_kms_key" "trust" {
  count                    = var.experimental_trust_enabled ? 1 : 0
  description              = "Registry experimental AI Catalog assertion key"
  customer_master_key_spec = "ECC_NIST_P256"
  key_usage                = "SIGN_VERIFY"
  deletion_window_in_days  = 30
  lifecycle {
    prevent_destroy = true
  }
}
resource "aws_kms_alias" "trust" {
  count         = var.experimental_trust_enabled ? 1 : 0
  name          = "alias/${local.name}-trust"
  target_key_id = aws_kms_key.trust[0].key_id
}
resource "aws_iam_role_policy" "trust" {
  count = var.experimental_trust_enabled ? 1 : 0
  name  = "experimental-trust-signing"
  role  = aws_iam_role.lambda.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = ["kms:GetPublicKey", "kms:Sign"]
      Resource = aws_kms_key.trust[0].arn
    }]
  })
}
