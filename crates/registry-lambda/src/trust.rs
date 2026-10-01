//! Dedicated KMS assertion key and bounded HTTPS fetch adapter.
use aithos_catalog_signatures::{crypto, fetch::Fetcher};
use async_trait::async_trait;
use p256::{ecdsa::VerifyingKey, pkcs8::DecodePublicKey};
use registry_api::trust::{HOST, TrustIo};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
pub struct KmsTrustIo {
    client: aws_sdk_kms::Client,
    key: String,
    kid: String,
    document: Value,
}
impl KmsTrustIo {
    pub async fn new(client: aws_sdk_kms::Client, key: &str, origin: &str) -> Result<Self, String> {
        let out = client
            .get_public_key()
            .key_id(key)
            .send()
            .await
            .map_err(|e| e.to_string())?;
        if out.key_spec() != Some(&aws_sdk_kms::types::KeySpec::EccNistP256)
            || out.key_usage() != Some(&aws_sdk_kms::types::KeyUsageType::SignVerify)
        {
            return Err("expected a P-256 signing key".into());
        }
        let key = out.key_id().ok_or("missing key ID")?.to_string();
        let public = VerifyingKey::from_public_key_der(
            out.public_key().ok_or("missing public key")?.as_ref(),
        )
        .map_err(|e| e.to_string())?;
        let point = public.to_encoded_point(false);
        let suffix = key.rsplit('/').next().ok_or("invalid key ID")?;
        let issuer = format!("did:web:{}", origin.trim_start_matches("https://"));
        let kid = format!("{issuer}#trust-{suffix}");
        let jwk = json!({"kty":"EC","crv":"P-256","alg":"ES256","use":"sig","key_ops":["verify"],"x":crypto::encode(point.x().unwrap()),"y":crypto::encode(point.y().unwrap())});
        let document = json!({"@context":["https://www.w3.org/ns/did/v1","https://w3id.org/security/suites/jws-2020/v1"],"id":issuer,"verificationMethod":[{"id":kid,"type":"JsonWebKey2020","controller":issuer,"publicKeyJwk":jwk}],"assertionMethod":[kid]});
        Ok(Self {
            client,
            key,
            kid,
            document,
        })
    }
}
#[async_trait]
impl TrustIo for KmsTrustIo {
    async fn fetch(&self, url: &str) -> Result<Vec<u8>, String> {
        let url = url.to_string();
        tokio::task::spawn_blocking(move || {
            Fetcher::new([HOST.into()])
                .and_then(|f| f.get(&url))
                .map_err(|e| e.to_string())
        })
        .await
        .map_err(|e| e.to_string())?
    }
    async fn sign(&self, input: &[u8]) -> Result<[u8; 64], String> {
        let out = self
            .client
            .sign()
            .key_id(&self.key)
            .signing_algorithm(aws_sdk_kms::types::SigningAlgorithmSpec::EcdsaSha256)
            .message_type(aws_sdk_kms::types::MessageType::Digest)
            .message(aws_sdk_kms::primitives::Blob::new(
                Sha256::digest(input).to_vec(),
            ))
            .send()
            .await
            .map_err(|e| e.to_string())?;
        crypto::der_to_jose(out.signature().ok_or("missing KMS signature")?.as_ref())
            .map_err(|e| e.to_string())
    }
    fn kid(&self) -> &str {
        &self.kid
    }
    fn did_document(&self) -> Value {
        self.document.clone()
    }
}
