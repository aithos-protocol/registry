//! `aithos` — publish and verify signed A2A Agent Cards.

mod card;
mod error;
mod keyfile;
mod verify;

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::time::Duration;

use clap::{Parser, Subcommand};
use serde_json::{Value, json};

use error::{Error, Result};
use keyfile::PrivateKey;

#[derive(Parser)]
#[command(
    name = "aithos",
    about = "Publish and verify signed A2A Agent Cards.",
    long_about = "Publish and verify signed A2A Agent Cards.\n\n\
                  An entry states that a card was published by the holder of a \
                  key, and that every version since was signed by a key that \
                  lineage authorized. It says nothing about any domain or \
                  organization.",
    version
)]
struct Cli {
    /// Registry to talk to.
    #[arg(
        long,
        global = true,
        env = "AITHOS_REGISTRY",
        default_value = "https://registry.aithos.world"
    )]
    registry: String,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Manage the keys that control your entries.
    #[command(subcommand)]
    Key(KeyCommand),

    /// Manage card files.
    #[command(subcommand)]
    Card(CardCommand),

    /// Sign a card and publish it.
    Publish {
        /// The card file.
        file: PathBuf,
        /// Key to sign with. Repeat it to authorize several: that is how a
        /// backup key is added and how a lost one is retired.
        #[arg(long = "key", required = true)]
        keys: Vec<String>,
        /// Raise the version before signing, since a registry refuses a
        /// publication that does not move forward.
        #[arg(long, value_parser = ["major", "minor", "patch"])]
        bump: Option<String>,
        /// Sign and write the result without contacting anything, so the
        /// machine holding the key never needs to reach the network.
        #[arg(long)]
        offline: bool,
        /// Where to write the signed card. Defaults to the input file.
        #[arg(long)]
        out: Option<PathBuf>,
        /// The entry to write to. Only needed for a card that has never been
        /// published from this registry, and even then only to adopt an entry
        /// created elsewhere.
        #[arg(long)]
        agent: Option<String>,
    },

    /// Check a published card, or a file, against its signatures.
    Verify {
        /// An agent identifier, a URL, or a path to a card file.
        target: String,
        /// A JWKS file whose keys are trusted. Without it, keys come from the
        /// card's own `jku`, which proves only that document and key agree.
        #[arg(long)]
        jwks: Option<PathBuf>,
    },
}

#[derive(Subcommand)]
enum KeyCommand {
    /// Generate a key. Its thumbprint becomes the identifier of any entry it
    /// creates, so you know the address before you publish anything.
    New {
        /// Leave the key unencrypted on disk.
        #[arg(long)]
        no_passphrase: bool,
    },
    /// List the keys on this machine.
    Ls,
}

#[derive(Subcommand)]
enum CardCommand {
    /// Write a minimal card that already satisfies the strict A2A profile.
    Init {
        #[arg(long, default_value = "agent-card.json")]
        out: PathBuf,
        #[arg(long, default_value = "My Agent")]
        name: String,
        #[arg(long, default_value = "https://agent.example/a2a")]
        url: String,
    },
    /// Validate a card locally, without publishing it.
    Check { file: PathBuf },
}

fn main() {
    if let Err(error) = run() {
        eprintln!("aithos: {error}");
        std::process::exit(1);
    }
}

fn run() -> Result<()> {
    let cli = Cli::parse();
    let registry = cli.registry.trim_end_matches('/').to_string();

    match cli.command {
        Command::Key(KeyCommand::New { no_passphrase }) => key_new(&registry, no_passphrase),
        Command::Key(KeyCommand::Ls) => key_ls(),
        Command::Card(CardCommand::Init { out, name, url }) => card_init(&out, &name, &url),
        Command::Card(CardCommand::Check { file }) => card_check(&file),
        Command::Publish {
            file,
            keys,
            bump,
            offline,
            out,
            agent,
        } => publish(
            &registry,
            &file,
            &keys,
            bump.as_deref(),
            offline,
            out.as_deref(),
            agent.as_deref(),
        ),
        Command::Verify { target, jwks } => run_verify(&registry, &target, jwks.as_deref()),
    }
}

// --- keys ----------------------------------------------------------------

fn key_new(registry: &str, no_passphrase: bool) -> Result<()> {
    let key = PrivateKey::generate();
    let kid = key.kid()?;
    let path = keyfile::key_path(&kid)?;

    let passphrase = if no_passphrase {
        None
    } else {
        Some(read_new_passphrase()?)
    };
    key.save(&path, passphrase.as_deref())?;

    println!("key      {kid}");
    println!("file     {}", path.display());
    println!("agent    {registry}/v1/agents/{kid}");
    println!();
    println!("This key is the only thing that can change an entry it creates.");
    println!("Register a second one before you need it: publish a version signed");
    println!("by both, and either can act alone from then on.");
    Ok(())
}

fn key_ls() -> Result<()> {
    let dir = keyfile::key_dir()?;
    let Ok(entries) = std::fs::read_dir(&dir) else {
        println!("no keys yet in {}", dir.display());
        return Ok(());
    };

    let mut rows: Vec<(String, bool)> = Vec::new();
    for entry in entries.flatten() {
        let path = entry.path();
        if path.extension().is_some_and(|e| e == "jwk")
            && let Some(kid) = path.file_stem().and_then(|s| s.to_str())
        {
            rows.push((
                kid.to_string(),
                PrivateKey::is_encrypted(&path).unwrap_or(true),
            ));
        }
    }
    rows.sort();

    if rows.is_empty() {
        println!("no keys yet in {}", dir.display());
        return Ok(());
    }
    for (kid, encrypted) in rows {
        println!(
            "{kid}  {}",
            if encrypted { "encrypted" } else { "PLAINTEXT" }
        );
    }
    Ok(())
}

fn read_new_passphrase() -> Result<String> {
    let first = rpassword::prompt_password("Passphrase for this key: ")?;
    if first.is_empty() {
        return Err(Error::msg(
            "an empty passphrase leaves the key in the clear; pass --no-passphrase if that is what you want",
        ));
    }
    let again = rpassword::prompt_password("Again: ")?;
    if first != again {
        return Err(Error::msg("the two passphrases differ"));
    }
    Ok(first)
}

fn load_key(kid: &str) -> Result<PrivateKey> {
    let path = keyfile::key_path(kid)?;
    PrivateKey::load(&path, || {
        Ok(rpassword::prompt_password(format!(
            "Passphrase for {kid}: "
        ))?)
    })
}

// --- cards ---------------------------------------------------------------

fn card_init(out: &std::path::Path, name: &str, url: &str) -> Result<()> {
    if out.exists() {
        return Err(Error::msg(format!("{} already exists", out.display())));
    }
    let card = card::scaffold(name, url);
    std::fs::write(out, serde_json::to_string_pretty(&card)? + "\n")?;
    println!("wrote {}", out.display());
    println!("Edit it, then `aithos card check {}`.", out.display());
    Ok(())
}

fn card_check(file: &std::path::Path) -> Result<()> {
    let card = card::load(file)?;
    println!("valid    {}", file.display());
    println!("name     {}", card.value["name"].as_str().unwrap_or("?"));
    println!("version  {}", card.card_version().unwrap_or("?"));
    println!("digest   {}", card.digest);
    let count = card.value["signatures"].as_array().map_or(0, Vec::len);
    println!("signed   {count} signature(s)");
    Ok(())
}

// --- publish -------------------------------------------------------------

fn publish(
    registry: &str,
    file: &std::path::Path,
    kids: &[String],
    bump: Option<&str>,
    offline: bool,
    out: Option<&std::path::Path>,
    agent: Option<&str>,
) -> Result<()> {
    let text = std::fs::read_to_string(file)
        .map_err(|e| Error::msg(format!("{}: {e}", file.display())))?;
    let mut body: Value = serde_json::from_str(&text)?;

    let keys: Vec<PrivateKey> = kids
        .iter()
        .map(|kid| load_key(kid))
        .collect::<Result<_>>()?;
    let refs: Vec<&PrivateKey> = keys.iter().collect();

    // The identifier belongs to the entry, never to whoever signs this version.
    // Deriving it from the signing key would silently turn a rotation into the
    // creation of a second, unrelated entry.
    let agent_id = match agent {
        Some(explicit) => explicit.to_string(),
        None => match card::agent_of(&body, registry) {
            Some(existing) => existing,
            None => keys[0].kid()?,
        },
    };
    println!("agent    {agent_id}");

    let existing = if offline {
        None
    } else {
        fetch_record(registry, &agent_id)?
    };

    if let Some(level) = bump {
        let version = card::bump(&mut body, level)?;
        println!("version  {version}");
    }

    let jku = format!("{registry}/v1/agents/{agent_id}/jwks.json");
    let signed = card::sign(&body, &refs, Some(&jku))?;

    // Signed before this check rather than after. The three accepted algorithms
    // are deterministic, so an unchanged card reproduces the published document
    // byte for byte — and refusing on the version alone would reject the one
    // case a registry takes without complaint: a client retrying a request
    // whose response was lost.
    if let Some(record) = &existing
        && record["cardDigest"].as_str() != Some(signed.digest.as_str())
        && let Ok(published) = record["cardVersion"]
            .as_str()
            .unwrap_or("0.0.0")
            .parse::<semver::Version>()
        && let Ok(proposed) = signed
            .card_version()
            .unwrap_or_default()
            .parse::<semver::Version>()
        && proposed <= published
    {
        return Err(Error::msg(format!(
            concat!(
                "this card differs from the published one but still says {proposed}, ",
                "and the entry already publishes {published}.\n\n",
                "A registry orders publications by version and will not take one that does not ",
                "move forward.\nAdd --bump patch, or set the version in the card yourself."
            ),
            proposed = proposed,
            published = published,
        )));
    }
    let destination = out.unwrap_or(file);
    std::fs::write(
        destination,
        String::from_utf8_lossy(&signed.bytes).to_string() + "\n",
    )?;

    println!("digest   {}", signed.digest);
    println!("wrote    {}", destination.display());

    if keys.len() == 1 {
        eprintln!();
        eprintln!("Warning: this entry will be controlled by one key. Losing it is");
        eprintln!("irreversible — no operator can restore access. Publish a version");
        eprintln!("signed by two keys while you still can.");
        eprintln!();
    }

    if offline {
        println!();
        println!(
            "Not published. Move {} to a machine with network access and run:",
            destination.display()
        );
        println!(
            "  aithos publish {} --agent {agent_id} --key <kid>",
            destination.display()
        );
        return Ok(());
    }

    let payload = json!({
        "agentCard": signed.value,
        "keys": keys.iter().map(|k| k.public_jwk()).collect::<Vec<_>>(),
    });
    let response = http()?
        .put(format!("{registry}/v1/agents/{agent_id}"))
        .json(&payload)
        .send()?;

    let status = response.status();
    let result: Value = serde_json::from_str(&response.text()?).unwrap_or(Value::Null);
    if !status.is_success() {
        return Err(Error::msg(format!(
            "the registry refused this card ({}): {}\n{}",
            status.as_u16(),
            result["code"].as_str().unwrap_or("?"),
            result["detail"].as_str().unwrap_or("")
        )));
    }

    let seq = result["seq"].as_u64().unwrap_or_default();
    let unchanged = existing
        .as_ref()
        .and_then(|r| r["seq"].as_u64())
        .is_some_and(|before| before == seq);

    if status.as_u16() == 201 {
        println!("created  sequence {seq}");
    } else if unchanged {
        println!("unchanged  this card is already published as sequence {seq}");
    } else {
        println!("updated  sequence {seq}");
    }
    println!("         {registry}/v1/agents/{agent_id}/agent-card.json");
    Ok(())
}

fn http() -> Result<reqwest::blocking::Client> {
    Ok(reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(30))
        .build()?)
}

/// Read an entry, if it exists. Knowing the published version before signing
/// turns a rejection after the fact into an explanation beforehand.
fn fetch_record(registry: &str, agent_id: &str) -> Result<Option<Value>> {
    let response = http()?
        .get(format!("{registry}/v1/agents/{agent_id}"))
        .send()?;
    if response.status().as_u16() == 404 {
        return Ok(None);
    }
    if !response.status().is_success() {
        return Ok(None);
    }
    Ok(Some(serde_json::from_str(&response.text()?)?))
}

// --- verify --------------------------------------------------------------

fn run_verify(registry: &str, target: &str, jwks: Option<&std::path::Path>) -> Result<()> {
    let (card, origin) = fetch_card(registry, target)?;

    let mut trusted = BTreeMap::new();
    if let Some(path) = jwks {
        let raw: Value = serde_json::from_str(&std::fs::read_to_string(path)?)?;
        let keys = raw["keys"]
            .as_array()
            .cloned()
            .unwrap_or_else(|| vec![raw.clone()]);
        for key in keys {
            let parsed = registry_core::Jwk::parse(&key)?;
            trusted.insert(parsed.thumbprint().to_string(), key);
        }
    }

    let report = verify::verify(&card, &trusted)?;

    println!("card     {} {}", report.name, report.version);
    if let Some(origin) = &origin {
        println!("from     {origin}");
    }
    println!("digest   {}", report.card_digest);
    println!("payload  {}", report.payload_digest);
    println!();

    for signature in &report.signatures {
        let source = match signature.source {
            Some(verify::KeySource::Trusted) => "key you supplied",
            Some(verify::KeySource::SelfDeclared) => "key named by the card",
            None => "no key",
        };
        match &signature.outcome {
            Ok(()) => println!(
                "  ok      {} [{}] via {source}",
                signature.kid, signature.alg
            ),
            Err(why) => println!("  FAILED  {} [{}] {why}", signature.kid, signature.alg),
        }
    }
    println!();

    if !report.any_verified() {
        return Err(Error::msg("no signature on this card verified"));
    }

    // What was established, and — the part that matters — what was not.
    if report.verified_against_trusted_key() {
        println!("This card was signed by a key you supplied out of band.");
    } else {
        println!("This card is internally consistent: it was signed by the key it names,");
        println!("fetched from the location it names. Both came from the same place, so");
        println!("this shows the document is intact, not who published it.");
    }
    println!();
    println!("Not established: any domain, any organisation, and whether whoever");
    println!("holds this key operates the endpoints the card declares.");
    Ok(())
}

fn fetch_card(registry: &str, target: &str) -> Result<(a2a_card::CanonicalCard, Option<String>)> {
    let path = std::path::Path::new(target);
    if path.exists() {
        return Ok((card::load(path)?, None));
    }

    let url = if target.starts_with("https://") || target.starts_with("http://") {
        target.to_string()
    } else {
        format!("{registry}/v1/agents/{target}/agent-card.json")
    };

    let response = http()?.get(&url).send()?;
    if !response.status().is_success() {
        return Err(Error::msg(format!("{url} answered {}", response.status())));
    }

    // Parsed from the exact bytes received: re-serializing before checking
    // would verify something the sender never sent.
    Ok((a2a_card::parse_card(&response.text()?)?, Some(url)))
}
