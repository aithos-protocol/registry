//! AWS backend for the Agent Card Registry.
//!
//! The read and write paths are deliberately asymmetric, because their traffic
//! is. Published cards are immutable and named by their digest, so the public
//! read surface is static objects served from S3 through CloudFront and never
//! reaches this code. Writes are rare and go through here.

pub mod aws_store;
pub mod item;
pub mod keys;

pub use aws_store::AwsStore;
