//! Write the static documents served beside the API.
//!
//!     cargo run -p registry-api --example gen-site
//!
//! Output goes to `site/`, which Terraform uploads to the object store. The
//! files are committed rather than generated at deploy time, so what is served
//! is what was reviewed; `tests/openapi.rs` fails when they stop matching this
//! catalogue, which is the reminder to run this again.

use std::fs;
use std::path::PathBuf;

use registry_api::catalog::{CATALOG, render_index, render_page};

fn main() -> std::io::Result<()> {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
    let problems = root.join("site/problems");
    fs::create_dir_all(&problems)?;

    // No extension: the `type` URI is `/problems/{slug}`, and a document served
    // at a different path from the one the API names is not documentation of
    // anything. Terraform sets the media type on upload.
    for doc in CATALOG {
        fs::write(problems.join(doc.slug()), render_page(doc))?;
    }
    fs::write(problems.join("index.html"), render_index())?;

    println!(
        "wrote {} problem pages to {}",
        CATALOG.len(),
        problems.display()
    );
    Ok(())
}
