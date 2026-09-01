//! Lambda entry point.
//!
//! One binary serves two roles, selected by `REGISTRY_ROLE`. They share the
//! key layout and the item mapping, and shipping them as one artifact means
//! they can never be deployed at different versions of it.

use std::sync::Arc;

use registry_api::{RegistryConfig, router};
use registry_dns::HickoryResolver;
use registry_lambda::{AwsStore, Reconciler};

/// Read a required setting, failing at boot rather than on the first request.
fn env(name: &str) -> Result<String, lambda_http::Error> {
    std::env::var(name).map_err(|_| format!("{name} is not set").into())
}

/// The resolver both roles resolve with (`DOMAIN-CERTIFICATION.md` §5.5).
///
/// The Lambda environment's own resolver by default; `REGISTRY_DNS_SERVERS`
/// (comma-separated IPs) forces one for development. Configuration only —
/// nothing request-shaped ever reaches this.
fn resolver() -> Result<HickoryResolver, lambda_http::Error> {
    match std::env::var("REGISTRY_DNS_SERVERS") {
        Ok(list) if !list.is_empty() => {
            let servers = list
                .split(',')
                .map(|s| s.trim().parse())
                .collect::<Result<Vec<std::net::IpAddr>, _>>()
                .map_err(|e| format!("REGISTRY_DNS_SERVERS: {e}"))?;
            HickoryResolver::with_servers(&servers).map_err(Into::into)
        }
        _ => HickoryResolver::from_system().map_err(Into::into),
    }
}

/// The revalidation interval the manifest publishes (§7). It has to match the
/// deployed schedule, so it comes from the environment the schedule's own
/// Terraform sets, with the current `rate(1 hour)` as the default.
fn revalidate_interval_seconds() -> u64 {
    std::env::var("REGISTRY_REVALIDATE_SECONDS")
        .ok()
        .and_then(|raw| raw.parse().ok())
        .unwrap_or(3600)
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
            // The distribution stamps every request it forwards with this
            // header. Without the check, the API's own `execute-api` hostname
            // is a second entrance that the edge rate rules never see — and
            // WAFv2 cannot be attached to an HTTP API, so there is no way to
            // put those rules on it.
            //
            // Required, not optional. A warning about an open front door is read
            // by nobody: "absent means no gate" fails to a silently ungated
            // origin with no WAF in front of it, which is the exact condition
            // the gate exists to prevent. Running without it is possible and has
            // to be said out loud, for a local run with no distribution.
            let edge_secret = match std::env::var("REGISTRY_EDGE_SECRET") {
                Ok(secret) if !secret.is_empty() => Some(secret),
                _ if std::env::var("REGISTRY_ALLOW_UNGATED_ORIGIN").as_deref() == Ok("yes") => {
                    tracing::warn!(
                        "running without the edge gate by explicit opt-out; this origin is \
                         reachable directly and no rate limit applies to it"
                    );
                    None
                }
                _ => {
                    return Err("REGISTRY_EDGE_SECRET must be set, or \
                                REGISTRY_ALLOW_UNGATED_ORIGIN=yes to run without the gate"
                        .into());
                }
            };

            let app = router(
                Arc::new(store),
                Arc::new(resolver()?),
                RegistryConfig {
                    origin,
                    revalidate_interval_seconds: revalidate_interval_seconds(),
                },
            );
            let app = match edge_secret {
                Some(secret) => app.layer(axum::middleware::from_fn(
                    move |req: axum::extract::Request, next: axum::middleware::Next| {
                        let secret = secret.clone();
                        async move {
                            let ok = req
                                .headers()
                                .get("x-aithos-edge")
                                .and_then(|v| v.to_str().ok())
                                .is_some_and(|v| {
                                    // Constant-time: the header is attacker-supplied
                                    // and a byte-at-a-time comparison leaks it.
                                    use subtle::ConstantTimeEq as _;
                                    v.as_bytes().ct_eq(secret.as_bytes()).into()
                                });
                            use axum::response::IntoResponse as _;
                            if ok {
                                next.run(req).await
                            } else {
                                registry_api::problem::Problem::new(
                                    403,
                                    "FORBIDDEN",
                                    "this registry is served through its public hostname",
                                )
                                .into_response()
                            }
                        }
                    },
                )),
                None => app,
            };
            lambda_http::run(app).await
        }

        // The periodic repair pass. Same binary, same reconciler, a different
        // input: committed state instead of a stream record. It exists because
        // a stream event-source mapping that exhausts its retries discards the
        // record, and what it writes to the failure destination is batch
        // metadata, not the record — so nothing else in the system could put
        // right a withdrawal the stream dropped.
        "sweeper" => {
            let store = Arc::new(AwsStore::new(
                aws_sdk_dynamodb::Client::new(&config),
                s3.clone(),
                env("REGISTRY_TABLE")?,
                bucket.clone(),
            ));
            let reconciler = Arc::new(Reconciler::new(s3, bucket));
            // The revalidation of certified domains (DOMAIN-CERTIFICATION.md
            // §7) rides the same hourly invocation: same enumeration, same
            // cadence the manifest publishes.
            let resolver: Arc<dyn registry_dns::Resolver> = Arc::new(resolver()?);
            lambda_runtime::run(lambda_runtime::service_fn(
                move |_event: lambda_runtime::LambdaEvent<serde_json::Value>| {
                    let reconciler = Arc::clone(&reconciler);
                    let store = Arc::clone(&store);
                    let resolver = Arc::clone(&resolver);
                    async move {
                        let ids = store
                            .sweep_agent_ids()
                            .await
                            .map_err(|e| -> lambda_runtime::Error { e.to_string().into() })?;
                        let repairs = reconciler
                            .sweep(store.as_ref(), &ids)
                            .await
                            .map_err(|e| -> lambda_runtime::Error { e.into() })?;

                        // Logged before anything is returned, including when
                        // the pass had failures: the metric filter that watches
                        // for drift reads this line, and a `?` above it meant a
                        // sweep that found drift *and* then failed reported no
                        // drift at all.
                        if repairs.is_empty() {
                            tracing::info!(agents = ids.len(), "read path matches the register");
                        } else {
                            // Not an error in itself — the sweep did its job.
                            // But an empty result is the expected one, so
                            // anything else means the stream lost a record, and
                            // that is worth waking someone for.
                            tracing::error!(
                                agents = ids.len(),
                                repaired = repairs.len(),
                                republished = ?repairs.republished,
                                withdrawn = ?repairs.withdrawn,
                                "the read path had drifted from the register"
                            );
                        }

                        // Run even when convergence found repairs: the two
                        // passes answer different questions, and a certified
                        // domain must not stay published an extra hour because
                        // an unrelated pointer needed rewriting.
                        let revalidation = registry_lambda::revalidate::run_pass(
                            store.as_ref() as &dyn registry_api::Store,
                            &resolver,
                            &ids,
                            &registry_api::api::now_rfc3339(),
                        )
                        .await;
                        tracing::info!(
                            examined = revalidation.examined,
                            removed = revalidation.removed.len(),
                            "revalidated certified domains"
                        );

                        let mut failures = repairs.failed.clone();
                        failures.extend(revalidation.failed.iter().cloned());
                        if !failures.is_empty() {
                            return Err(format!(
                                "{} of {} agents could not be converged or revalidated: {}",
                                failures.len(),
                                ids.len(),
                                failures.join("; ")
                            )
                            .into());
                        }

                        Ok::<_, lambda_runtime::Error>(serde_json::json!({
                            "agents": ids.len(),
                            "repaired": repairs.len(),
                            "revalidated": revalidation.examined,
                            "domainsRemoved": revalidation.removed.len(),
                        }))
                    }
                },
            ))
            .await
        }

        "reconciler" => {
            let store = Arc::new(AwsStore::new(
                aws_sdk_dynamodb::Client::new(&config),
                s3.clone(),
                env("REGISTRY_TABLE")?,
                bucket.clone(),
            ));
            let reconciler = Arc::new(Reconciler::new(s3, bucket));
            lambda_runtime::run(lambda_runtime::service_fn(
                move |event: lambda_runtime::LambdaEvent<serde_json::Value>| {
                    let reconciler = Arc::clone(&reconciler);
                    let store = Arc::clone(&store);
                    async move {
                        let applied = reconciler
                            .handle(store.as_ref(), &event.payload)
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
