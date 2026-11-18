use regex::Regex;
use serde::Deserialize;
use std::io::{self, BufRead};
use std::process::{exit, Command};

#[derive(Deserialize, Default)]
struct Config {
    #[serde(default)]
    names: Vec<String>,
    #[serde(default)]
    rules: Vec<CustomRule>,
}

#[derive(Deserialize)]
struct CustomRule {
    name: String,
    pattern: String,
}

struct Rule {
    name: String,
    re: Regex,
}

fn load_config(path: &str) -> Config {
    match std::fs::read_to_string(path) {
        Ok(text) => match toml::from_str(&text) {
            Ok(cfg) => cfg,
            Err(e) => {
                eprintln!("veil: could not read {}: {}", path, e);
                exit(2);
            }
        },
        Err(_) => Config::default(),
    }
}

fn build_rules(cfg: &Config) -> Vec<Rule> {
    let defs = [
        ("secret", r"(?i)(api[_-]?key|token|secret|password)\s*[=:]\s*\S+"),
        ("email", r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}"),
        ("iban", r"\b[A-Z]{2}\d{2} ?(?:[A-Z0-9]{4} ?){3,7}[A-Z0-9]{1,4}\b"),
        ("insurance_id", r"\b[A-Z]\d{9}\b"),
        ("date", r"\b(?:\d{2}\.\d{2}\.\d{4}|\d{4}-\d{2}-\d{2})\b"),
        ("phone", r"(?:\+|00)\d{1,3}[ -]?\d{2,5}[ -]?\d{3,}"),
    ];
    let mut list: Vec<Rule> = defs
        .iter()
        .map(|&(name, pat)| Rule {
            name: name.to_string(),
            re: Regex::new(pat).unwrap(),
        })
        .collect();

    for r in &cfg.rules {
        match Regex::new(&r.pattern) {
            Ok(re) => list.push(Rule { name: r.name.clone(), re }),
            Err(e) => {
                eprintln!("veil: bad pattern for rule '{}': {}", r.name, e);
                exit(2);
            }
        }
    }

    if !cfg.names.is_empty() {
        let alternatives: Vec<String> = cfg.names.iter().map(|n| regex::escape(n)).collect();
        let pattern = format!(r"(?i)\b(?:{})\b", alternatives.join("|"));
        list.push(Rule {
            name: "name".to_string(),
            re: Regex::new(&pattern).unwrap(),
        });
    }
    list
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
    let cfg_path = flags
        .iter()
        .position(|a| a == "--config")
        .and_then(|i| flags.get(i + 1))
        .map(|s| s.as_str())
        .unwrap_or("veil.toml");

    let cfg = load_config(cfg_path);
    let rules = build_rules(&cfg);
    let mut counts = vec![0usize; rules.len()];

    // Mode 1: veil run [--report] [--config file] -- <command> [args...]
    if args.first().map(|s| s.as_str()) == Some("run") {
        let cmd_args = match sep {
            Some(p) if p + 1 < args.len() => &args[p + 1..],
            _ => {
                eprintln!("usage: veil run [--report] [--config file] -- <command> [args...]");
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
