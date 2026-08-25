//! Lambda entry point.

use std::sync::Arc;

use registry_api::{RegistryConfig, router};
use registry_lambda::AwsStore;

/// Read a required setting, failing at boot rather than on the first request.
fn env(name: &str) -> Result<String, lambda_http::Error> {
    std::env::var(name).map_err(|_| format!("{name} is not set").into())
}

#[tokio::main]
async fn main() -> Result<(), lambda_http::Error> {
    tracing_subscriber::fmt()
        .json()
        .with_max_level(tracing::Level::INFO)
        // CloudWatch adds its own timestamp to every line.
        .without_time()
        .with_target(false)
        .init();

    let table = env("REGISTRY_TABLE")?;
    let bucket = env("REGISTRY_BUCKET")?;
    let origin = env("REGISTRY_ORIGIN")?;
    if !origin.starts_with("https://") || origin.ends_with('/') {
        return Err("REGISTRY_ORIGIN must be an https origin with no trailing slash".into());
    }

    let config = aws_config::load_defaults(aws_config::BehaviorVersion::latest()).await;
    let store = AwsStore::new(
        aws_sdk_dynamodb::Client::new(&config),
        aws_sdk_s3::Client::new(&config),
        table,
        bucket,
    );

    let app = router(Arc::new(store), RegistryConfig { origin });
    lambda_http::run(app).await
}
