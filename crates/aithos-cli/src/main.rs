//! `aithos` — publish and verify signed A2A Agent Cards.

mod card;
mod certify;
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

/// Where the tool points when nobody says otherwise: the public registry.
///
/// Named as a constant because two places must agree on it — the clap default,
/// and the transport-error hint that explains what to do while this hostname
/// is not open yet.
const DEFAULT_REGISTRY: &str = "https://registry.aithos.world";

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
    #[arg(long, global = true, env = "AITHOS_REGISTRY", default_value = DEFAULT_REGISTRY)]
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
        /// Sign and write the result without contacting the registry, so the
        /// machine holding the key never needs to reach it. The signed card
        /// and its proofs are written to the file; publishing them still
        /// requires this command, with the same keys, from a machine that can.
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

    /// Withdraw an entry. Permanent, and the identifier is never reusable.
    Withdraw {
        /// The entry to withdraw.
        agent: String,
        /// A key currently authorized for the entry.
        #[arg(long = "key")]
        key: String,
        /// Skip the confirmation prompt. There is no undo.
        #[arg(long)]
        yes: bool,
    },

    /// Certify domains for an entry: each domain declares the agent in its
    /// own DNS zone, and a key holder signs the request.
    Certify {
        /// The entry to certify domains for.
        agent: String,
        /// A key currently authorized for the entry.
        #[arg(long = "key")]
        key: String,
        /// The complete set of domains, comma-separated, in A-label form.
        /// The set replaces the set — name the ones to keep. `--domains ""`
        /// removes every certification.
        #[arg(long, value_delimiter = ',', required = true)]
        domains: Vec<String>,
    },

    /// Look up what a registry holds at an address, the way `whois` does.
    Whatis {
        /// An agent identifier.
        agent: String,
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

/// Reject a registry origin the rest of the tool cannot work against.
///
/// `sign` stamps `jku = {registry}/v1/agents/{id}/jwks.json`, and §5.5 requires
/// `jku` to be HTTPS — so an `http://` registry produced `422 SIGNATURE_INVALID`
/// on every write, sending the publisher to look at their key rather than at
/// their `--registry` flag.
fn check_registry(registry: &str) -> Result<()> {
    // No trailing-slash check: `run()` trims trailing slashes before anything
    // sees the value, so testing for one here was a branch no input could
    // reach.
    if !registry.starts_with("https://") {
        return Err(Error::msg(format!(
            "{registry:?} is not usable as a registry origin: it must be an https URL.\n\n\
             Cards carry a `jku` pointing back at the registry, and §5.5 requires that to \
             be HTTPS."
        )));
    }
    Ok(())
}

/// A request that never got an answer, explained.
///
/// reqwest's own text names the URL and the OS error, which is right and not
/// enough: while the public registry is not open yet, the very first thing a
/// fresh install does is resolve a name that does not exist, and the message
/// for that must say what to do — not send the publisher to check their DNS.
fn transport_error(url: &str, error: &reqwest::Error) -> Error {
    let mut message = format!("{url}: {error}");
    if url.starts_with(DEFAULT_REGISTRY) && (error.is_connect() || error.is_timeout()) {
        message.push_str(
            "\n\nThis is the tool's default registry, and the public registry is not open \
             yet. Point the tool at one you can reach: --registry <origin>, or \
             AITHOS_REGISTRY in the environment.",
        );
    }
    Error::msg(message)
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
        } => {
            check_registry(&registry)?;
            publish(
                &registry,
                &file,
                &keys,
                bump.as_deref(),
                offline,
                out.as_deref(),
                agent.as_deref(),
            )
        }
        Command::Withdraw { agent, key, yes } => {
            check_registry(&registry)?;
            withdraw(&registry, &agent, &key, yes)
        }
        Command::Certify {
            agent,
            key,
            domains,
        } => {
            check_registry(&registry)?;
            run_certify(&registry, &agent, &key, &domains)
        }
        Command::Whatis { agent } => {
            check_registry(&registry)?;
            whatis(&registry, &agent)
        }
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
    let card = card::scaffold(name, url)?;
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
    match a2a_card_sdk::decode(&card) {
        Ok(_) => println!("a2a sdk  readable by the official A2A SDK, round trip exact"),
        Err(e) => println!("a2a sdk  warning: {e}"),
    }
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
    // The same strict profile the registry applies, and that `aithos card
    // check` already applied. A permissive parse here was worse than anywhere
    // else in the tool: a duplicate member is resolved silently by keeping the
    // last one, so `"name": "Mine"` followed by `"name": "Impostor"` was
    // *signed* as "Impostor" — with the author's key, and then written back
    // over the author's file. The registry cannot catch it, because by the time
    // it sees the card the duplicate is gone.
    let mut body: Value = a2a_card::strict::parse(&text)
        .map_err(|e| Error::msg(format!("{}: {e}", file.display())))?;

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
        && registry_core::precedence(&proposed) <= registry_core::precedence(&published)
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
    println!("digest   {}", signed.digest);

    if keys.len() == 1 {
        eprintln!();
        eprintln!("Warning: this entry will be controlled by one key. Losing it is");
        eprintln!("irreversible — no operator can restore access. Publish a version");
        eprintln!("signed by two keys while you still can.");
        eprintln!();
    }

    // Written only once the write is known to be one the registry would take.
    // Replacing the operator's own file and *then* discovering the publication
    // is refused leaves them with a document they did not ask for in place of
    // the one they wrote — and `agent_of` reads the entry identifier out of the
    // input card's own `jku`, so a card from a third party can steer where this
    // was aimed.
    let write_result = |signed: &a2a_card::CanonicalCard| -> Result<()> {
        write_atomically(destination, &signed.bytes)?;
        println!("wrote    {}", destination.display());
        Ok(())
    };

    if offline {
        write_result(&signed)?;
        println!();
        println!(
            "Not published. The signed card is in {}.",
            destination.display()
        );
        println!();
        // Publishing needs the same keys again: §6.2 requires a proof from each
        // one, bound to this registry and this digest, and those cannot be
        // carried in the card. Saying "move the file and publish from there"
        // would be advice that does not work.
        println!("To publish it, run this from a machine that can reach the registry");
        println!("and has the same key(s):");
        println!(
            "  aithos publish {} --agent {agent_id} {}",
            destination.display(),
            kids.iter()
                .map(|k| format!("--key {k}"))
                .collect::<Vec<_>>()
                .join(" ")
        );
        return Ok(());
    }

    // §6.2: every key that enters the authorized set signs a payload naming
    // this registry, this identifier and this exact card. Signing the card is
    // not enough — a card signature names no registry, so it cannot say where
    // its signer wanted the card published.
    check_provers(&refs, &agent_id, existing.as_ref())?;
    let proofs = refs
        .iter()
        .map(|key| card::publication_proof(key, registry, &agent_id, &signed.digest))
        .collect::<Result<Vec<_>>>()?;
    let payload = json!({
        "agentCard": signed.value,
        "keys": keys.iter().map(|k| k.public_jwk()).collect::<Vec<_>>(),
        "proofs": proofs,
    });
    let put_url = format!("{registry}/v1/agents/{agent_id}");
    let response = http()?
        .put(&put_url)
        .json(&payload)
        .send()
        .map_err(|e| transport_error(&put_url, &e))?;

    let status = response.status();
    if status.is_success() {
        write_result(&signed)?;
    }
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
    let url = format!("{registry}/v1/agents/{agent_id}");
    let response = http()?
        .get(&url)
        .send()
        .map_err(|e| transport_error(&url, &e))?;
    let status = response.status();
    if status.as_u16() == 404 {
        return Ok(None);
    }
    // Anything else is not "no such entry". Reporting a 410 or a 503 as absence
    // sent the publisher the creation advice — "creating {id} needs its genesis
    // key" — for an entry that exists and is withdrawn, or for a registry that
    // is briefly down. The local diagnostic exists to be right in exactly these
    // cases.
    if !status.is_success() {
        let body: Value = serde_json::from_str(&response.text()?).unwrap_or(Value::Null);
        return Err(Error::msg(format!(
            "{registry} answered {} for {agent_id}: {}\n{}",
            status.as_u16(),
            body["code"].as_str().unwrap_or("?"),
            body["detail"].as_str().unwrap_or("")
        )));
    }
    Ok(Some(serde_json::from_str(&response.text()?)?))
}

// --- withdraw ------------------------------------------------------------

/// Withdraw an entry (§6.5).
///
/// The registry holds no key, so nobody but the key holder can do this — which
/// is the point, and also why the tool has to be able to: without it the only
/// route is hand-assembling a detached JWS, and a publisher who cannot remove
/// their own entry is a publisher who was never really in control of it.
fn withdraw(registry: &str, agent_id: &str, key_name: &str, yes: bool) -> Result<()> {
    let record = fetch_record(registry, agent_id)?
        .ok_or_else(|| Error::msg(format!("{registry} has no entry {agent_id}")))?;
    let digest = record["cardDigest"]
        .as_str()
        .ok_or_else(|| Error::msg("the registry did not report a current card digest"))?;

    println!("agent    {agent_id}");
    println!("version  {}", record["cardVersion"].as_str().unwrap_or("?"));
    println!("digest   {digest}");

    if !yes {
        eprintln!();
        eprintln!("Withdrawing is permanent. The card and its key set stop being served,");
        eprintln!("and this identifier can never be used again — not by you, not by anyone.");
        eprintln!("Every published version stays readable at its own digest.");
        eprintln!();
        eprint!("Type the agent identifier to confirm: ");
        use std::io::Write as _;
        std::io::stderr().flush()?;
        let mut typed = String::new();
        std::io::stdin().read_line(&mut typed)?;
        if typed.trim() != agent_id {
            return Err(Error::msg(
                "that is not the identifier; nothing was withdrawn",
            ));
        }
    }

    let key = load_key(key_name)?;
    let withdrawal = card::withdrawal(&key, registry, agent_id, digest)?;
    let payload = json!({
        "withdrawal": withdrawal,
        "keys": [key.public_jwk()],
    });

    let delete_url = format!("{registry}/v1/agents/{agent_id}");
    let response = http()?
        .delete(&delete_url)
        .json(&payload)
        .send()
        .map_err(|e| transport_error(&delete_url, &e))?;
    let status = response.status();
    let result: Value = serde_json::from_str(&response.text()?).unwrap_or(Value::Null);
    if !status.is_success() {
        return Err(Error::msg(format!(
            "the registry refused this withdrawal ({}): {}\n{}",
            status.as_u16(),
            result["code"].as_str().unwrap_or("?"),
            result["detail"].as_str().unwrap_or("")
        )));
    }

    println!("withdrawn");
    println!("         history stays readable at {registry}/v1/agents/{agent_id}/versions");
    Ok(())
}

// --- certify -------------------------------------------------------------

/// Certify domains (`DOMAIN-CERTIFICATION.md`, Appendix A).
///
/// Local validation first, then a look at DNS from *this* machine: a missing
/// record is reported with the exact zone lines to paste, and nothing is sent
/// — a publisher waiting on propagation hears it from their own resolver, not
/// from a rejected request. The registry resolves everything again itself;
/// this check is a courtesy, never the proof.
fn run_certify(
    registry: &str,
    agent_id: &str,
    key_name: &str,
    raw_domains: &[String],
) -> Result<()> {
    let domains = certify::parse_domains(raw_domains)?;

    let record = fetch_record(registry, agent_id)?
        .ok_or_else(|| Error::msg(format!("{registry} holds no entry {agent_id}")))?;
    let authorized: Vec<&str> = record["authorizedKids"]
        .as_array()
        .map(|a| a.iter().filter_map(Value::as_str).collect())
        .unwrap_or_default();

    println!("agent    {agent_id}");

    // The same courtesy `publish` extends: refuse here, with an explanation,
    // rather than collect a 403 from a server nobody can ask questions of.
    let key = load_key(key_name)?;
    let kid = key.kid()?;
    if !authorized.contains(&kid.as_str()) {
        return Err(Error::msg(format!(
            "key {kid} is not currently authorized for {agent_id}.\n\n\
             The entry currently trusts: {}.",
            if authorized.is_empty() {
                "(the registry did not say)".to_string()
            } else {
                authorized.join(", ")
            }
        )));
    }

    if domains.is_empty() {
        println!("domains  (none — removing every certification)");
    } else {
        // What does this machine's DNS say?
        let sightings = certify::sight_from_here(agent_id, &domains)?;
        let mut missing = Vec::new();
        let mut unresolved = Vec::new();
        for (domain, sighting) in &sightings {
            match sighting {
                certify::Sighting::Declares => println!("domain   {domain}  declares this agent"),
                certify::Sighting::Absent => {
                    println!("domain   {domain}  no record visible from here");
                    missing.push(domain);
                }
                certify::Sighting::Unresolved(why) => {
                    println!("domain   {domain}  could not be resolved from here ({why})");
                    unresolved.push(domain);
                }
            }
        }

        if !missing.is_empty() {
            println!();
            println!("Add these records, then run the same command again:");
            println!();
            print!("{}", certify::zone_lines(agent_id, &missing));
            println!();
            println!("Leave them published: they are the evidence, not a one-time challenge —");
            println!("removing one withdraws the certification. If you just added them, your");
            println!("resolver may simply not see them yet.");
            return Err(Error::msg("nothing was sent"));
        }
        if !unresolved.is_empty() {
            println!();
            println!("Nothing can be concluded about the domains above from this machine.");
            println!("Nothing was sent; retry when your resolver can answer.");
            return Err(Error::msg("nothing was sent"));
        }
    }

    let operation = certify::certification(&key, registry, agent_id, &domains)?;
    let payload = json!({
        "certification": operation,
        "keys": [key.public_jwk()],
    });
    let url = format!("{registry}/v1/agents/{agent_id}/domains");
    let response = http()?
        .put(&url)
        .json(&payload)
        .send()
        .map_err(|e| transport_error(&url, &e))?;
    let status = response.status();
    let result: Value = serde_json::from_str(&response.text()?).unwrap_or(Value::Null);
    if !status.is_success() {
        let mut message = format!(
            "the registry refused this certification ({}): {}\n{}",
            status.as_u16(),
            result["code"].as_str().unwrap_or("?"),
            result["detail"].as_str().unwrap_or("")
        );
        // The per-domain outcomes of §11, so a multi-domain refusal never
        // needs bisecting.
        if let Some(outcomes) = result["domains"].as_array() {
            for entry in outcomes {
                message.push_str(&format!(
                    "\n  {}  {}",
                    entry["domain"].as_str().unwrap_or("?"),
                    entry["outcome"].as_str().unwrap_or("?")
                ));
            }
        }
        return Err(Error::msg(message));
    }

    let listed = result["domains"].as_array().cloned().unwrap_or_default();
    if listed.is_empty() {
        println!("certified  (no domains)");
    } else {
        println!("certified");
        for entry in &listed {
            println!(
                "         {}  since {}",
                entry["domain"].as_str().unwrap_or("?"),
                entry["certifiedAt"].as_str().unwrap_or("?")
            );
        }
    }
    println!();
    println!("The registry re-resolves these hourly; a removed record withdraws its");
    println!("certification within a few passes. A certified domain establishes what");
    println!("its zone declares — nothing about endpoints or organizations.");
    Ok(())
}

// --- whatis --------------------------------------------------------------

/// What a registry holds at one address.
///
/// The `whois` analogy is the right one, and it is worth taking seriously in
/// both directions. `whois` reports registration facts — when a name was
/// registered, who may change it, whether it is still active — and it reports
/// nothing about whether the thing at that name is honest. This is the same
/// shape, and the same limit.
///
/// So the output separates two kinds of statement, and the separation is
/// visible rather than documented. Above the line are facts the registry
/// establishes: the address, its status, its lineage, whether the current card
/// verifies. Below it is whatever the key holder wrote in their card, which
/// nobody checked and which a reader must not take as identity. A lookup tool
/// that printed a self-declared organisation name beside a green tick would be
/// a phishing instrument with this registry's name on it (`SPEC.md` §10).
fn whatis(registry: &str, agent_id: &str) -> Result<()> {
    let record = fetch_record(registry, agent_id)?
        .ok_or_else(|| Error::msg(format!("{registry} holds no entry {agent_id}")))?;

    let field = |name: &str| record[name].as_str().unwrap_or("?").to_string();
    let status = field("status");
    let withdrawn = status == "WITHDRAWN";

    println!("address    {agent_id}");
    println!("status     {status}");
    println!("registry   {registry}");
    println!();

    println!("registered {}", field("createdAt"));
    println!("updated    {}", field("updatedAt"));
    let versions = version_count(registry, agent_id).unwrap_or(0);
    println!(
        "versions   {versions}, current {} (sequence {})",
        field("cardVersion"),
        record["seq"].as_u64().unwrap_or(0)
    );

    // The set of keys that may change this entry — the part of a `whois`
    // answer that actually matters, and the only identity claim made here.
    let authorized: Vec<&str> = record["authorizedKids"]
        .as_array()
        .map(|a| a.iter().filter_map(Value::as_str).collect())
        .unwrap_or_default();
    for (i, kid) in authorized.iter().enumerate() {
        println!("{} {kid}", if i == 0 { "keys      " } else { "          " });
    }
    println!();

    if withdrawn {
        println!("This entry was withdrawn by its key holder. Its card and its key set");
        println!("are no longer served, and the address can never be reused. Every");
        println!("version it published stays readable at its own digest.");
        return Ok(());
    }

    // Verification is the one place the tool does work rather than relaying.
    match fetch_card(registry, agent_id) {
        Err(e) => {
            println!("card       not being served yet: {e}");
            println!();
            println!("The entry is committed. A card reaches the public read path a moment");
            println!("later, so this resolves on its own; if it does not, the registry has");
            println!("drifted from its own register.");
            return Ok(());
        }
        Ok((card, _)) => {
            let report = verify::verify(&card, &BTreeMap::new())?;
            println!("card       {}", report.card_digest);
            for signature in &report.signatures {
                match &signature.outcome {
                    Ok(()) => println!("signature  ok, by {} [{}]", signature.kid, signature.alg),
                    Err(why) => println!("signature  FAILED {} — {why}", signature.kid),
                }
            }
            println!();

            println!("Declared by the key holder. Nobody checked any of it:");
            println!("  name         {}", report.name);
            if let Some(d) = card.value["description"].as_str() {
                println!("  description  {d}");
            }
            if let Some(interfaces) = card.value["supportedInterfaces"].as_array() {
                for i in interfaces {
                    println!(
                        "  interface    {} {}",
                        i["protocolBinding"].as_str().unwrap_or("?"),
                        i["url"].as_str().unwrap_or("?")
                    );
                }
            }
            if let Some(skills) = card.value["skills"].as_array() {
                println!("  skills       {}", skills.len());
            }
            println!();
        }
    }

    println!("Established: the holder of an authorized key published this card here,");
    println!("and every version since was signed by a key that lineage authorized.");
    println!("Not established: any domain, any organisation, and whether whoever holds");
    println!("these keys operates the endpoints declared above.");
    Ok(())
}

/// How many versions the entry has published. Best effort: a lookup that
/// cannot count them is still worth printing without.
fn version_count(registry: &str, agent_id: &str) -> Option<usize> {
    let response = http()
        .ok()?
        .get(format!("{registry}/v1/agents/{agent_id}/versions"))
        .send()
        .ok()?;
    if !response.status().is_success() {
        return None;
    }
    let body: Value = serde_json::from_str(&response.text().ok()?).ok()?;
    body["versions"].as_array().map(Vec::len)
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
        // An anchor file holding no keys is a mistake, not an instruction to
        // fall back. `verify` decides whether an anchor was given by whether
        // the set is non-empty, so `{"keys": []}` would silently reopen the
        // `jku` fetch the operator scoped out — the request itself, not only
        // the verdict.
        if trusted.is_empty() {
            return Err(Error::msg(format!(
                "{} holds no keys; there is nothing to verify against",
                path.display()
            )));
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

    // When an anchor was supplied, the question asked was "is this signed by a
    // key I hold?", and only that answer may exit zero. Reporting success
    // because the card verified against a key the card itself named answers a
    // different question, and every `aithos verify … && deploy` in the world
    // reads only the exit status.
    if jwks.is_some() && !report.verified_against_trusted_key() {
        return Err(Error::msg(
            "no signature on this card verified against the keys you supplied",
        ));
    }
    if !report.any_verified() {
        return Err(Error::msg("no signature on this card verified"));
    }

    // Certified domains, only when the target is an entry: the *list* comes
    // from the record, but every verdict below is resolved live by this
    // client and never read back from the registry — a certification the
    // reader cannot reproduce is one they would have to take on faith
    // (`DOMAIN-CERTIFICATION.md`, Appendix A).
    let domains_shown = match target_kind(target) {
        Target::AgentId => print_certified_domains(registry, target)?,
        _ => false,
    };

    // What was established, and — the part that matters — what was not.
    if report.verified_against_trusted_key() {
        println!("This card was signed by a key you supplied out of band.");
    } else {
        println!("This card is internally consistent: it was signed by the key it names,");
        println!("fetched from the location it names. Both came from the same place, so");
        println!("this shows the document is intact, not who published it.");
    }
    println!();
    if domains_shown {
        println!("Not established: any organisation, whether whoever holds this key");
        println!("operates the endpoints the card declares, or anything about a domain");
        println!("beyond the record its zone publishes.");
    } else {
        println!("Not established: any domain, any organisation, and whether whoever");
        println!("holds this key operates the endpoints the card declares.");
    }
    Ok(())
}

/// The certified-domain lines of `verify`. True when any line was printed.
///
/// A-labels exactly as stored, never rendered as U-labels, and no tick of any
/// kind: the honest rendering is a domain, a date, and what this machine's
/// resolver just saw (§9).
fn print_certified_domains(registry: &str, agent_id: &str) -> Result<bool> {
    let Some(record) = fetch_record(registry, agent_id)? else {
        return Ok(false);
    };
    let listed = record["domains"].as_array().cloned().unwrap_or_default();
    if listed.is_empty() {
        return Ok(false);
    }

    let mut domains = Vec::new();
    for entry in &listed {
        let raw = entry["domain"].as_str().unwrap_or_default();
        match registry_core::Domain::parse(raw) {
            Ok(domain) => domains.push((domain, entry["certifiedAt"].as_str().unwrap_or("?"))),
            // A stored domain this client cannot even parse is not one it can
            // re-check; say so rather than resolve something else.
            Err(_) => println!("domain   {raw:?}  cannot be re-checked (unparseable)"),
        }
    }

    let sightings = certify::sight_from_here(
        agent_id,
        &domains.iter().map(|(d, _)| d.clone()).collect::<Vec<_>>(),
    )?;
    for ((domain, certified_at), (_, sighting)) in domains.iter().zip(sightings) {
        match sighting {
            certify::Sighting::Declares => println!(
                "domain   {domain}  declared by its zone, re-checked now (certified since {certified_at})"
            ),
            certify::Sighting::Absent => println!(
                "domain   {domain}  listed by the registry, but no record is visible from here"
            ),
            certify::Sighting::Unresolved(why) => {
                println!("domain   {domain}  could not be re-checked from here ({why})")
            }
        }
    }
    println!();
    Ok(true)
}

/// What a `verify` target is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Target {
    Url,
    File,
    AgentId,
}

/// Decide how a `verify` target should be read.
///
/// URLs are decided **first**, and the order is the point: every URL contains
/// `/` and a card URL ends in `.json`, so the path heuristic below swallowed
/// them all — `aithos verify <url>`, which `--help` promises, answered "no
/// such file" for every URL there is. The heuristic itself stays, for the
/// reason it exists: testing `exists()` first meant an identifier shadowed by
/// a local file of the same name was read silently — a right answer about the
/// wrong document.
fn target_kind(target: &str) -> Target {
    if target.starts_with("https://") || target.starts_with("http://") {
        return Target::Url;
    }
    if target.contains(std::path::MAIN_SEPARATOR)
        || target.starts_with('.')
        || target.ends_with(".json")
    {
        return Target::File;
    }
    Target::AgentId
}

fn fetch_card(registry: &str, target: &str) -> Result<(a2a_card::CanonicalCard, Option<String>)> {
    let url = match target_kind(target) {
        Target::File => {
            let path = std::path::Path::new(target);
            if !path.exists() {
                return Err(Error::msg(format!("{target}: no such file")));
            }
            return Ok((card::load(path)?, Some(format!("file {target}"))));
        }
        // The point of verifying is to learn where a document came from. Over
        // plain HTTP that answer is whatever the network chose to give.
        Target::Url if target.starts_with("http://") => {
            return Err(Error::msg(format!(
                "{target} is not HTTPS; a card fetched over plain HTTP tells you nothing about \
                 where it came from"
            )));
        }
        Target::Url => target.to_string(),
        Target::AgentId => {
            check_registry(registry)?;
            format!("{registry}/v1/agents/{target}/agent-card.json")
        }
    };

    let response = http()?
        .get(&url)
        .send()
        .map_err(|e| transport_error(&url, &e))?;
    if !response.status().is_success() {
        return Err(Error::msg(format!("{url} answered {}", response.status())));
    }

    // Bounded while reading, like the `jku` fetch, and for the same reason: the
    // URL came from outside, so a host that streams without end must not be
    // able to exhaust this process. Buffering in order to measure is the attack
    // rather than the defence against it.
    const MAX: u64 = 512 * 1024;
    let mut buffer = Vec::new();
    std::io::copy(&mut std::io::Read::take(response, MAX + 1), &mut buffer)?;
    if buffer.len() as u64 > MAX {
        return Err(Error::msg(format!("{url} returned more than 512 KiB")));
    }

    // From the exact bytes, decoded strictly. `reqwest::text()` substitutes
    // U+FFFD for invalid UTF-8, which would have this tool report a digest of a
    // document nobody sent — the one thing it exists not to do.
    let text = String::from_utf8(buffer)
        .map_err(|_| Error::msg(format!("{url} did not return valid UTF-8")))?;
    Ok((a2a_card::parse_card(&text)?, Some(url)))
}

/// Refuse a write the registry will refuse, and say why here rather than as a
/// 403 from a server the publisher cannot ask questions of.
///
/// The rule is not "the genesis key always works": after a rotation away from
/// it, the genesis key still *names* the entry but is no longer authorized for
/// it. Only the absence of an existing entry makes the genesis key the one that
/// matters.
fn check_provers(keys: &[&PrivateKey], agent_id: &str, existing: Option<&Value>) -> Result<()> {
    let mut kids = Vec::new();
    for key in keys {
        kids.push(key.kid()?);
    }

    let Some(record) = existing else {
        return if kids.iter().any(|kid| kid == agent_id) {
            Ok(())
        } else {
            Err(Error::msg(format!(
                "creating {agent_id} needs its genesis key, and none of the keys you signed \
                 with ({}) is it.\n\nA new entry is named after the key that opens it.",
                kids.join(", ")
            )))
        };
    };

    let authorized: Vec<&str> = record["authorizedKids"]
        .as_array()
        .map(|a| a.iter().filter_map(Value::as_str).collect())
        .unwrap_or_default();
    if kids.iter().any(|kid| authorized.contains(&kid.as_str())) {
        return Ok(());
    }
    Err(Error::msg(format!(
        "none of the keys you signed with ({}) is currently authorized for {agent_id}.\n\n\
         The entry currently trusts: {}.",
        kids.join(", "),
        if authorized.is_empty() {
            "(the registry did not say)".to_string()
        } else {
            authorized.join(", ")
        }
    )))
}

/// Write a file by creating a sibling and renaming it over the target.
///
/// `rename` within one directory is atomic, so a reader — or an interrupted
/// run — sees either the old file or the new one, never a truncated one.
fn write_atomically(path: &std::path::Path, bytes: &[u8]) -> Result<()> {
    use std::io::Write as _;

    let directory = path.parent().unwrap_or_else(|| std::path::Path::new("."));
    let name = path
        .file_name()
        .ok_or_else(|| Error::msg(format!("{} is not a file path", path.display())))?;
    let temporary = directory.join(format!(".{}.tmp", name.to_string_lossy()));

    {
        let mut file = std::fs::File::create(&temporary)?;
        file.write_all(bytes)?;
        file.write_all(b"\n")?;
        file.sync_all()?;
    }
    std::fs::rename(&temporary, path).map_err(|e| {
        let _ = std::fs::remove_file(&temporary);
        Error::msg(format!("{}: {e}", path.display()))
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    /// The genesis key names the entry forever, but it is not authorized for it
    /// forever: after a rotation away from it, a write it proves is refused.
    /// Treating "kid == agentId" as sufficient sent the publisher a 403 from a
    /// server they cannot ask questions of.
    #[test]
    fn the_genesis_key_stops_qualifying_once_it_is_rotated_out() {
        let genesis = PrivateKey::generate();
        let backup = PrivateKey::generate();
        let agent_id = genesis.kid().unwrap();

        // Before the entry exists, only the genesis key will do.
        check_provers(&[&genesis], &agent_id, None).expect("genesis creates its own entry");
        check_provers(&[&backup], &agent_id, None).unwrap_err();

        // After rotating to the backup key, the genesis key no longer qualifies.
        let rotated = json!({ "authorizedKids": [backup.kid().unwrap()] });
        check_provers(&[&genesis], &agent_id, Some(&rotated))
            .expect_err("a retired genesis key must not be offered to the registry");
        check_provers(&[&backup], &agent_id, Some(&rotated)).expect("the current key qualifies");

        // Re-adding the genesis key as a backup: legitimate, and it works
        // because the *authorized* key is among the signers.
        check_provers(&[&genesis, &backup], &agent_id, Some(&rotated))
            .expect("re-adding the old key, co-signed by the current one");
    }

    /// The routing `--help` promises: an identifier, a URL, or a path. The
    /// round-10 bounded-fetch rework left the URL arm unreachable — every URL
    /// contains `/`, so the path heuristic claimed it first and
    /// `verify <url>` answered "no such file" for every URL there is.
    #[test]
    fn a_url_target_is_a_url_not_a_missing_file() {
        assert_eq!(
            target_kind("https://r.example/v1/agents/x/agent-card.json"),
            Target::Url
        );
        // Refused later for being plain HTTP — but refused as a URL, with the
        // reason, not as a file that does not exist.
        assert_eq!(target_kind("http://r.example/card.json"), Target::Url);
        assert_eq!(target_kind("./agent-card.json"), Target::File);
        assert_eq!(target_kind("cards/agent-card.json"), Target::File);
        assert_eq!(target_kind("agent-card.json"), Target::File);
        assert_eq!(
            target_kind("NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs"),
            Target::AgentId
        );
    }

    #[test]
    fn a_withdrawal_is_bound_to_the_registry_and_the_current_card() {
        let key = PrivateKey::generate();
        let w = card::withdrawal(&key, "https://r.example", "agent-1", "sha256:abc").unwrap();
        let payload = w["payload"].as_str().unwrap();
        let decoded = a2a_card::canonical::b64url_decode(payload).unwrap();
        let value: Value = serde_json::from_slice(&decoded).unwrap();

        assert_eq!(value["action"], "withdraw");
        assert_eq!(value["agentId"], "agent-1");
        assert_eq!(value["cardDigest"], "sha256:abc");
        assert_eq!(value["registryOrigin"], "https://r.example");
        assert!(value["issuedAt"].is_string());
    }
}
