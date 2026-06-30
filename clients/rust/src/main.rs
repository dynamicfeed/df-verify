//! CLI for the DF-VERIFY/1 Rust reference verifier.
//!
//!   dynamicfeed-verify <response.json> <keys.json>   verify a saved signed response
//!   dynamicfeed-verify --canonical <file.json>        print the canonical bytes
//!
//! Keys are the `key_id -> base64url public key` map from
//! https://dynamicfeed.ai/.well-known/keys (fetch with curl; the verifier itself
//! has no network dependency, so you can verify fully offline).
use dynamicfeed_verify::{canonical, parse, verify};
use std::{env, fs, process};

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() == 3 && args[1] == "--canonical" {
        let v = parse(&read(&args[2])).unwrap_or_else(die);
        print!("{}", String::from_utf8_lossy(&canonical(&v)));
        return;
    }
    if args.len() == 3 {
        let env_v = parse(&read(&args[1])).unwrap_or_else(die);
        let keys_v = parse(&read(&args[2])).unwrap_or_else(die);
        let keys = match keys_v.as_object() {
            Some(m) => m.clone(),
            None => die("keys file is not a JSON object".into()),
        };
        match verify(&env_v, &keys) {
            Ok(true) => {
                println!("VERIFIED: signature is valid (bytes intact). Note: signed is not verified.");
                process::exit(0);
            }
            Ok(false) => {
                eprintln!("INVALID: signature did not verify (data may be altered).");
                process::exit(1);
            }
            Err(e) => die(e),
        }
    }
    eprintln!(
        "usage:\n  dynamicfeed-verify <response.json> <keys.json>\n  dynamicfeed-verify --canonical <file.json>"
    );
    process::exit(2);
}

fn read(p: &str) -> String {
    fs::read_to_string(p).unwrap_or_else(|e| die(format!("read {p}: {e}")))
}

fn die<T>(msg: String) -> T {
    eprintln!("error: {msg}");
    process::exit(2);
}
