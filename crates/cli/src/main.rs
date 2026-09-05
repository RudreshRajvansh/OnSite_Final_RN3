use clap::{Parser, Subcommand};
use engine::{permissiveness, verify, Net, Observation, VerifyOptions, VerifyOutcome};
use std::path::PathBuf;
use std::process::ExitCode;

const DEFAULT_SPEC: &str = "spec/release.wsl.yaml";

#[derive(Parser)]
#[command(name = "maskedrunner", version, about = "workflow integrity verification")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    Lint {
        #[arg(long, default_value = DEFAULT_SPEC)]
        spec: PathBuf,
    },
    Verify {
        #[arg(long, default_value = DEFAULT_SPEC)]
        spec: PathBuf,
        #[arg(long)]
        observation: PathBuf,
        #[arg(long, default_value_t = 0)]
        slack: usize,
        #[arg(long)]
        json: bool,
    },
    Permissiveness {
        #[arg(long, default_value = DEFAULT_SPEC)]
        spec: PathBuf,
        #[arg(long, default_value_t = 12)]
        depth: usize,
        #[arg(long, default_value_t = 100_000)]
        cap: usize,
    },
}

fn main() -> ExitCode {
    match Cli::parse().command {
        Command::Lint { spec } => run_lint(spec),
        Command::Verify {
            spec,
            observation,
            slack,
            json,
        } => run_verify(spec, observation, slack, json),
        Command::Permissiveness { spec, depth, cap } => run_permissiveness(spec, depth, cap),
    }
}

fn run_lint(path: PathBuf) -> ExitCode {
    let loaded = match wsl::load(&path) {
        Ok(l) => l,
        Err(e) => return fail(&e.to_string()),
    };
    println!("SPEC      {}", loaded.short_hash());
    println!(
        "PLACES    {}   TRANSITIONS  {}",
        loaded.spec.places.len(),
        loaded.spec.transitions.len()
    );
    for d in &loaded.report.diagnostics {
        let tag = match d.severity {
            wsl::Severity::Error => "ERROR  ",
            wsl::Severity::Warning => "WARNING",
        };
        println!("{} {}  {}", tag, d.code, d.message);
    }
    if loaded.report.is_sound() {
        println!("VERDICT   SOUND");
        ExitCode::SUCCESS
    } else {
        println!("VERDICT   UNSOUND");
        ExitCode::from(1)
    }
}

fn run_verify(spec: PathBuf, observation: PathBuf, slack: usize, json: bool) -> ExitCode {
    let loaded = match wsl::load_checked(&spec) {
        Ok(l) => l,
        Err(e) => return fail(&e.to_string()),
    };
    let obs = match Observation::load(&observation) {
        Ok(o) => o,
        Err(e) => return fail(&e.to_string()),
    };
    let net = Net::compile(&loaded.spec);

    let options = VerifyOptions::for_observation(&obs, slack);
    let outcome = verify(&net, &obs, options);

    let robust = if outcome.accepted() {
        None
    } else {
        let mut wide = VerifyOptions::for_observation(&obs, obs.records.len() + 4);
        wide.max_states = 400_000;
        Some(!verify(&net, &obs, wide).accepted())
    };

    if json {
        let payload = serde_json::json!({
            "run_id": obs.run_id,
            "spec": loaded.short_hash(),
            "spec_hash": loaded.hash,
            "observation_hash": obs.hash(),
            "robust": robust,
            "outcome": outcome,
        });
        println!("{}", serde_json::to_string_pretty(&payload).unwrap());
    } else {
        report(&loaded, &obs, &outcome, robust);
    }

    if outcome.accepted() {
        ExitCode::SUCCESS
    } else {
        ExitCode::from(1)
    }
}

fn report(
    loaded: &wsl::LoadedSpec,
    obs: &Observation,
    outcome: &VerifyOutcome,
    robust: Option<bool>,
) {
    let verdict = if outcome.accepted() { "ACCEPT" } else { "REJECT" };
    match robust {
        Some(true) => println!("VERDICT   {}  (robust: holds at maximum slack)", verdict),
        Some(false) => println!("VERDICT   {}  (explainable by unobserved steps)", verdict),
        None => println!("VERDICT   {}", verdict),
    }
    if let Some(witness) = &outcome.witness {
        println!("WITNESS   {}", outcome.witness_path());
        for step in witness {
            let source = match &step.record {
                Some(r) => r.clone(),
                None => "unobserved".to_string(),
            };
            let bindings: Vec<String> = step
                .bindings
                .iter()
                .filter(|(k, _)| !k.starts_with('_'))
                .map(|(k, v)| format!("{}={}", k, v))
                .collect();
            println!(
                "            {:<26} {:<20} [{}] {}",
                step.transition,
                step.principal,
                source,
                bindings.join(" ")
            );
        }
    }
    if !outcome.failures.is_empty() {
        println!("FAILED OBLIGATION");
        for f in &outcome.failures {
            println!("  {}", f.render());
        }
    }
    println!(
        "BOUND     k={}, slack={}{}",
        outcome.bound,
        outcome.slack,
        if outcome.exhausted {
            "  (state cap reached)"
        } else {
            ""
        }
    );
    println!("STATES    {}", outcome.states_explored);
    println!("SPEC      {}", loaded.short_hash());
    println!("RUN       {}  sha256:{}", obs.run_id, &obs.hash()[..12]);
}

fn run_permissiveness(spec: PathBuf, depth: usize, cap: usize) -> ExitCode {
    let loaded = match wsl::load_checked(&spec) {
        Ok(l) => l,
        Err(e) => return fail(&e.to_string()),
    };
    let net = Net::compile(&loaded.spec);
    let measured = permissiveness(&net, depth, cap);
    println!("SPEC      {}", loaded.short_hash());
    println!(
        "ACCEPTS   {}{} structurally distinct executions at depth {}",
        measured.shapes,
        if measured.truncated { "+" } else { "" },
        measured.depth
    );
    println!("SOURCE    {} lines of declared workflow", loaded.spec.transitions.len());
    ExitCode::SUCCESS
}

fn fail(message: &str) -> ExitCode {
    eprintln!("error: {}", message);
    ExitCode::from(2)
}
