use regex::Regex;
use std::io::{self, BufRead};
use std::process::{exit, Command};

struct Rule {
    name: &'static str,
    re: Regex,
}

fn rules() -> Vec<Rule> {
    let defs = [
        ("secret", r"(?i)(api[_-]?key|token|secret|password)\s*[=:]\s*\S+"),
        ("email", r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}"),
        ("iban", r"\b[A-Z]{2}\d{2} ?(?:[A-Z0-9]{4} ?){3,7}[A-Z0-9]{1,4}\b"),
        ("insurance_id", r"\b[A-Z]\d{9}\b"),
        ("date", r"\b(?:\d{2}\.\d{2}\.\d{4}|\d{4}-\d{2}-\d{2})\b"),
        ("phone", r"(?:\+|00)\d{1,3}[ -]?\d{2,5}[ -]?\d{3,}"),
    ];
    defs.iter()
        .map(|&(name, pat)| Rule { name, re: Regex::new(pat).unwrap() })
        .collect()
}

fn redact(text: &str, rules: &[Rule], counts: &mut [usize]) -> String {
    let mut out = text.to_string();
    for (i, rule) in rules.iter().enumerate() {
        counts[i] += rule.re.find_iter(&out).count();
        let tag = format!("[REDACTED:{}]", rule.name);
        out = rule.re.replace_all(&out, tag.as_str()).into_owned();
    }
    out
}

fn print_report(rules: &[Rule], counts: &[usize]) {
    eprintln!("--- veil report ---");
    for (i, rule) in rules.iter().enumerate() {
        if counts[i] > 0 {
            eprintln!("{}: {}", rule.name, counts[i]);
        }
    }
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let sep = args.iter().position(|a| a == "--");
    let flags = match sep {
        Some(p) => &args[..p],
        None => &args[..],
    };
    let report = flags.iter().any(|a| a == "--report");
    let rules = rules();
    let mut counts = vec![0usize; rules.len()];

    // Mode 1: veil run [--report] -- <command> [args...]
    if args.first().map(|s| s.as_str()) == Some("run") {
        let cmd_args = match sep {
            Some(p) if p + 1 < args.len() => &args[p + 1..],
            _ => {
                eprintln!("usage: veil run [--report] -- <command> [args...]");
                exit(2);
            }
        };
        match Command::new(&cmd_args[0]).args(&cmd_args[1..]).output() {
            Ok(o) => {
                let stdout = String::from_utf8_lossy(&o.stdout);
                let stderr = String::from_utf8_lossy(&o.stderr);
                print!("{}", redact(&stdout, &rules, &mut counts));
                eprint!("{}", redact(&stderr, &rules, &mut counts));
                if report {
                    print_report(&rules, &counts);
                }
                exit(o.status.code().unwrap_or(1));
            }
            Err(e) => {
                eprintln!("veil: failed to run {}: {}", cmd_args[0], e);
                exit(127);
            }
        }
    }

    // Mode 2: pipe text in, get clean text out
    let stdin = io::stdin();
    for line in stdin.lock().lines() {
        let line = line.unwrap();
        println!("{}", redact(&line, &rules, &mut counts));
    }
    if report {
        print_report(&rules, &counts);
    }
}
