//! Lambda entry point.
//!
//! One binary serves two roles, selected by `REGISTRY_ROLE`. They share the
//! key layout and the item mapping, and shipping them as one artifact means
//! they can never be deployed at different versions of it.

use std::sync::Arc;

use registry_api::{RegistryConfig, router};
use registry_lambda::{AwsStore, Reconciler};

/// Read a required setting, failing at boot rather than on the first request.
fn env(name: &str) -> Result<String, lambda_http::Error> {
    std::env::var(name).map_err(|_| format!("{name} is not set").into())
}

#[tokio::main]
async fn main() -> Result<(), lambda_http::Error> {
    tracing_subscriber::fmt()
        .json()
        .with_max_level(tracing::Level::INFO)
        // CloudWatch stamps every line with its own timestamp.
        .without_time()
        .with_target(false)
        .init();

    let bucket = env("REGISTRY_BUCKET")?;
    let config = aws_config::load_defaults(aws_config::BehaviorVersion::latest()).await;
    let s3 = aws_sdk_s3::Client::new(&config);

    match env("REGISTRY_ROLE")?.as_str() {
        "api" => {
            let origin = env("REGISTRY_ORIGIN")?;
            if !origin.starts_with("https://") || origin.ends_with('/') {
                return Err(
                    "REGISTRY_ORIGIN must be an https origin with no trailing slash".into(),
                );
            }
            let store = AwsStore::new(
                aws_sdk_dynamodb::Client::new(&config),
                s3,
                env("REGISTRY_TABLE")?,
                bucket,
            );
            lambda_http::run(router(Arc::new(store), RegistryConfig { origin })).await
        }

        "reconciler" => {
            let reconciler = Arc::new(Reconciler::new(s3, bucket));
            lambda_runtime::run(lambda_runtime::service_fn(
                move |event: lambda_runtime::LambdaEvent<serde_json::Value>| {
                    let reconciler = Arc::clone(&reconciler);
                    async move {
                        let applied = reconciler
                            .handle(&event.payload)
                            .await
                            .map_err(|error| -> lambda_runtime::Error { error.into() })?;
                        tracing::info!(applied, "reconciled current-version pointers");
                        Ok::<_, lambda_runtime::Error>(())
                    }
                },
            ))
            .await
        }

        other => {
            Err(format!("REGISTRY_ROLE is {other:?}; expected \"api\" or \"reconciler\"").into())
        }
    }
}
