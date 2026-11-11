use regex::RegexBuilder;
use std::env;
use std::io::{self, BufRead, Write};

fn check_pattern(pattern: &str) -> Result<(), regex::Error> {
    RegexBuilder::new(pattern).dfa_size_limit(524288).build().map(|_| ())
}

fn main() {
    let arg = env::args().nth(1).expect("Missing regex pattern or --batch flag");

    if arg == "--batch" {
        let stdin = io::stdin();
        let mut stdout = io::stdout();
        for line in stdin.lock().lines() {
            match line {
                Ok(pat) => {
                    let trimmed = pat.trim_end_matches(&['\r', '\n'][..]);
                    match check_pattern(trimmed) {
                        Ok(_) => {
                            let _ = writeln!(stdout, "OK");
                        }
                        Err(e) => {
                            let _ = writeln!(stdout, "ERR {}", e.to_string().replace('\n', " "));
                        }
                    }
                    let _ = stdout.flush();
                }
                Err(_) => break,
            }
        }
        return;
    }

    // Single-pattern CLI mode (Cloudflare's exact engine parameters and 512KB memory limit)
    match check_pattern(&arg) {
        Ok(_) => std::process::exit(0),
        Err(e) => {
            eprintln!("{}", e);
            std::process::exit(1);
        }
    }
}
