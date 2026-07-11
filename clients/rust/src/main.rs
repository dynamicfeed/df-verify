//! dynamicfeed-verify — verify DF-VERIFY/1 signature bytes and signer lifecycle policy.
//!
//! Usage:
//!     dynamicfeed-verify [FILE] --registry <pinned-registry.json>
//!     dynamicfeed-verify [FILE] --registry-url <url>      (requires the `fetch` feature)
//!     dynamicfeed-verify [FILE] --key <base64-pubkey> --crypto-only
//!
//! FILE defaults to "-" (stdin). With the `fetch` feature and no --key/--keys-url,
//! lifecycle policy is fetched from the no-store signing-key registry.
//! Flat key input is mathematical verification only and requires explicit `--crypto-only`.

use std::io::Read;
use std::process::ExitCode;

const USAGE: &str = "usage: dynamicfeed-verify [FILE|-] [--registry FILE | --registry-url URL]\n\
                     [--historical-snapshot] [--minimum-registry-revision N]\n\
                     [--highest-authenticated-registry-revision N] [--registry-source-authenticated]\n\
                     dynamicfeed-verify [FILE|-] (--key PUBKEY | --keys-url URL) --crypto-only\n\
                     policy mode exits 0 only when signature + lifecycle pass. crypto-only mode\n\
                     is explicit and never claims signer lifecycle acceptance.";

fn positive_revision(value: String, name: &str) -> Result<u64, String> {
    value
        .parse::<u64>()
        .ok()
        .filter(|value| *value > 0)
        .ok_or_else(|| format!("{name} must be a positive integer"))
}

fn run() -> Result<bool, String> {
    let mut file: Option<String> = None;
    let mut key: Option<String> = None;
    let mut keys_url: Option<String> = None;
    let mut registry_file: Option<String> = None;
    let mut registry_url: Option<String> = None;
    let mut crypto_only = false;
    let mut verification_mode = dynamicfeed_verify::VerificationMode::Live;
    let mut minimum_registry_revision: Option<u64> = None;
    let mut highest_authenticated_registry_revision: Option<u64> = None;
    let mut registry_source_authenticated = false;

    let mut args = std::env::args().skip(1);
    while let Some(a) = args.next() {
        match a.as_str() {
            "--key" => key = Some(args.next().ok_or("--key needs a value")?),
            "--keys-url" => keys_url = Some(args.next().ok_or("--keys-url needs a value")?),
            "--registry" => registry_file = Some(args.next().ok_or("--registry needs a value")?),
            "--registry-url" => {
                registry_url = Some(args.next().ok_or("--registry-url needs a value")?)
            }
            "--crypto-only" => crypto_only = true,
            "--historical-snapshot" => {
                verification_mode = dynamicfeed_verify::VerificationMode::HistoricalSnapshot
            }
            "--minimum-registry-revision" => {
                minimum_registry_revision = Some(positive_revision(
                    args.next()
                        .ok_or("--minimum-registry-revision needs a value")?,
                    "--minimum-registry-revision",
                )?)
            }
            "--highest-authenticated-registry-revision" => {
                highest_authenticated_registry_revision = Some(positive_revision(
                    args.next()
                        .ok_or("--highest-authenticated-registry-revision needs a value")?,
                    "--highest-authenticated-registry-revision",
                )?)
            }
            "--registry-source-authenticated" => registry_source_authenticated = true,
            "-h" | "--help" => {
                println!("{USAGE}");
                std::process::exit(0);
            }
            _ if file.is_none() => file = Some(a),
            other => return Err(format!("unexpected argument '{other}'\n{USAGE}")),
        }
    }

    let text = match file.as_deref() {
        None | Some("-") => {
            let mut buf = String::new();
            std::io::stdin()
                .read_to_string(&mut buf)
                .map_err(|e| format!("could not read stdin — {e}"))?;
            buf
        }
        Some(path) => {
            std::fs::read_to_string(path).map_err(|e| format!("could not read {path} — {e}"))?
        }
    };

    if key.is_some() || keys_url.is_some() {
        if !crypto_only {
            return Err("flat key input has no lifecycle policy; add --crypto-only to request only Ed25519 mathematics, or supply --registry".into());
        }
        let verification = if let Some(pubkey) = key {
            dynamicfeed_verify::verify_envelope(&text, &pubkey).map_err(|e| e.to_string())?
        } else {
            #[cfg(feature = "fetch")]
            {
                let keys = dynamicfeed_verify::fetch_keys(keys_url.as_deref().unwrap())
                    .map_err(|e| e.to_string())?;
                dynamicfeed_verify::verify_with_keys(&text, &keys).map_err(|e| e.to_string())?
            }
            #[cfg(not(feature = "fetch"))]
            {
                return Err("this build has no network support for --keys-url".into());
            }
        };
        if verification.valid {
            println!(
                "CRYPTO_VALID  LIFECYCLE_UNCHECKED  key_id={}",
                verification.key_id
            );
            return Ok(true);
        }
        println!("CRYPTO_INVALID  key_id={}", verification.key_id);
        return Ok(false);
    }

    let options = dynamicfeed_verify::RegistryValidationOptions {
        mode: verification_mode,
        minimum_registry_revision,
        highest_authenticated_registry_revision,
        registry_source_authenticated,
    };
    let registry = if let Some(path) = registry_file {
        let raw = std::fs::read_to_string(&path)
            .map_err(|e| format!("could not read lifecycle registry {path} — {e}"))?;
        dynamicfeed_verify::LifecycleRegistry::parse_with_options(&raw, options)
            .map_err(|e| e.to_string())?
    } else {
        #[cfg(feature = "fetch")]
        {
            let url = registry_url
                .unwrap_or_else(|| dynamicfeed_verify::DEFAULT_LIFECYCLE_URL.to_string());
            let fetch_options = dynamicfeed_verify::RegistryValidationOptions {
                registry_source_authenticated: registry_source_authenticated
                    || url == dynamicfeed_verify::DEFAULT_LIFECYCLE_URL,
                ..options
            };
            dynamicfeed_verify::LifecycleRegistry::fetch_with_options(&url, fetch_options)
                .map_err(|e| e.to_string())?
        }
        #[cfg(not(feature = "fetch"))]
        {
            let _ = registry_url;
            return Err(format!(
                "this build has no network support — pass --registry FILE, or rebuild \
                 with `cargo build --features fetch` to use --registry-url\n{USAGE}"
            ));
        }
    };
    let verification =
        dynamicfeed_verify::verify_with_registry(&text, &registry).map_err(|e| e.to_string())?;
    if verification.accepted {
        println!(
            "POLICY_ACCEPTED  key_id={}  lifecycle={:?}  registry_revision={}  rollback_protected={}  anchor_authenticated={:?}",
            verification.key_id,
            verification.lifecycle_status,
            verification.registry_revision,
            verification.rollback_protected,
            verification.anchor_authenticated
        );
        Ok(true)
    } else if verification.crypto_valid {
        println!(
            "CRYPTO_VALID  LIFECYCLE_REJECTED  key_id={}  lifecycle={:?}  historical_snapshot={}  policy_as_of_accepted={}  registry_revision={}  anchor_authenticated={:?}",
            verification.key_id,
            verification.lifecycle_status,
            verification.historical_snapshot,
            verification.policy_as_of_accepted,
            verification.registry_revision,
            verification.anchor_authenticated
        );
        Ok(false)
    } else {
        println!("CRYPTO_INVALID  key_id={}", verification.key_id);
        Ok(false)
    }
}

fn main() -> ExitCode {
    match run() {
        Ok(true) => ExitCode::from(0),
        Ok(false) => ExitCode::from(1),
        Err(msg) => {
            eprintln!("error: {msg}");
            ExitCode::from(1)
        }
    }
}
