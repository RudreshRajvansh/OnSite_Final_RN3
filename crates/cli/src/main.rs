use clap::{Parser, Subcommand};
use engine::{permissiveness, verify, Net, Observation, VerifyOptions, VerifyOutcome};
use explain::{explain, sign, verify_signature, Certificate, SignedCertificate};
use std::path::PathBuf;
use std::process::ExitCode;

const DEFAULT_SPEC: &str = "spec/release.wsl.yaml";
const DEFAULT_MAP: &str = "spec/adapter.map.json";

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
        #[arg(long)]
        certificate: Option<PathBuf>,
    },
    Permissiveness {
        #[arg(long, default_value = DEFAULT_SPEC)]
        spec: PathBuf,
        #[arg(long, default_value_t = 12)]
        depth: usize,
        #[arg(long, default_value_t = 100_000)]
        cap: usize,
        #[arg(long, default_value_t = 2_000_000)]
        budget: usize,
    },
    Check {
        #[arg(long)]
        certificate: PathBuf,
    },
    Mutate {
        #[arg(long, default_value = DEFAULT_SPEC)]
        spec: PathBuf,
        #[arg(long)]
        observation: PathBuf,
        #[arg(long, default_value_t = 0)]
        slack: usize,
    },
    Ingest {
        #[arg(long)]
        bundle: PathBuf,
        #[arg(long, default_value = DEFAULT_MAP)]
        map: PathBuf,
        #[arg(long)]
        out: Option<PathBuf>,
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
            certificate,
        } => run_verify(spec, observation, slack, json, certificate),
        Command::Permissiveness {
            spec,
            depth,
            cap,
            budget,
        } => run_permissiveness(spec, depth, cap, budget),
        Command::Check { certificate } => run_check(certificate),
        Command::Ingest { bundle, map, out } => run_ingest(bundle, map, out),
        Command::Mutate {
            spec,
            observation,
            slack,
        } => run_mutate(spec, observation, slack),
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

fn run_verify(
    spec: PathBuf,
    observation: PathBuf,
    slack: usize,
    json: bool,
    certificate: Option<PathBuf>,
) -> ExitCode {
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

    let issued = explain(
        &net,
        &loaded.spec.workflow,
        &loaded.hash,
        &obs,
        &outcome,
        robust,
    );

    if json {
        println!("{}", serde_json::to_string_pretty(&issued).unwrap());
    } else {
        report(&loaded, &obs, &outcome, robust, &issued);
    }

    if let Some(path) = certificate {
        match sign(issued).and_then(|signed| {
            serde_json::to_string_pretty(&signed)
                .map_err(|e| explain::CertificateError::Encoding(e.to_string()))
        }) {
            Ok(body) => {
                if let Err(e) = std::fs::write(&path, body) {
                    return fail(&e.to_string());
                }
                println!("CERTIFICATE {}", path.display());
            }
            Err(e) => return fail(&e.to_string()),
        }
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
    issued: &Certificate,
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
    if !issued.minimal_unsatisfiable_set.is_empty() {
        println!(
            "MINIMAL UNSATISFIABLE SET   ({} oracle calls{})",
            issued.mus_oracle_calls,
            if issued.mus_minimal {
                ""
            } else {
                ", not reduced to a local minimum"
            }
        );
        for (i, fact) in issued.minimal_unsatisfiable_set.iter().enumerate() {
            println!("  [{}] {}", i + 1, fact.render());
        }
    }
    for note in &issued.notes {
        println!("NOTE      {}", note);
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

fn run_permissiveness(spec: PathBuf, depth: usize, cap: usize, budget: usize) -> ExitCode {
    let loaded = match wsl::load_checked(&spec) {
        Ok(l) => l,
        Err(e) => return fail(&e.to_string()),
    };
    let net = Net::compile(&loaded.spec);
    println!("SPEC      {}", loaded.short_hash());
    println!(
        "SOURCE    {} places, {} transitions",
        loaded.spec.places.len(),
        loaded.spec.transitions.len()
    );
    println!("DEPTH     DISTINCT EFFECT-GRAPH SHAPES");
    let mut last = None;
    for level in 1..=depth {
        let measured = permissiveness(&net, level, cap, budget);
        println!(
            "  {:<7} {}{}",
            level,
            measured.shapes,
            if measured.truncated { "+" } else { "" }
        );
        last = Some(measured);
        if last.as_ref().map(|m| m.truncated).unwrap_or(false) {
            break;
        }
    }
    if let Some(measured) = last {
        println!(
            "ACCEPTS   {}{} structurally distinct executions at depth {}",
            measured.shapes,
            if measured.truncated { "+" } else { "" },
            measured.depth
        );
        println!(
            "LANGUAGE  infinite: the net contains a cycle, so no depth bounds the accepted set"
        );
    }
    ExitCode::SUCCESS
}

fn run_mutate(spec: PathBuf, observation: PathBuf, slack: usize) -> ExitCode {
    let loaded = match wsl::load_checked(&spec) {
        Ok(l) => l,
        Err(e) => return fail(&e.to_string()),
    };
    let obs = match Observation::load(&observation) {
        Ok(o) => o,
        Err(e) => return fail(&e.to_string()),
    };

    let baseline = verify(
        &Net::compile(&loaded.spec),
        &obs,
        VerifyOptions::for_observation(&obs, slack),
    );
    println!("SPEC      {}", loaded.short_hash());
    println!("RUN       {}", obs.run_id);
    println!(
        "BASELINE  {}",
        if baseline.accepted() { "ACCEPT" } else { "REJECT" }
    );
    if baseline.accepted() {
        println!("Mutation testing measures which clause causes a rejection; this run is accepted.");
        return ExitCode::SUCCESS;
    }

    let mutants = wsl::mutants(&loaded.spec);
    let mut load_bearing: Vec<&wsl::Mutant> = Vec::new();
    println!("MUTANT                                                           VERDICT");
    for mutant in &mutants {
        let mutated = wsl::apply(&loaded.spec, &[&mutant.mutation]);
        if !wsl::lint(&mutated).is_sound() {
            println!("  {:<62} unsound", mutant.id);
            continue;
        }
        let outcome = verify(
            &Net::compile(&mutated),
            &obs,
            VerifyOptions::for_observation(&obs, slack),
        );
        println!(
            "  {:<62} {}",
            mutant.id,
            if outcome.accepted() { "ACCEPT" } else { "REJECT" }
        );
        if outcome.accepted() {
            load_bearing.push(mutant);
        }
    }

    if !load_bearing.is_empty() {
        println!(
            "RESULT    {} of {} single mutations remove the rejection",
            load_bearing.len(),
            mutants.len()
        );
        for mutant in &load_bearing {
            println!("  {}", mutant.description);
        }
        return ExitCode::SUCCESS;
    }

    println!(
        "RESULT    0 of {} single mutations remove the rejection",
        mutants.len()
    );
    let mut pairs = Vec::new();
    for (i, first) in mutants.iter().enumerate() {
        for second in mutants.iter().skip(i + 1) {
            let mutated = wsl::apply(&loaded.spec, &[&first.mutation, &second.mutation]);
            if !wsl::lint(&mutated).is_sound() {
                continue;
            }
            let outcome = verify(
                &Net::compile(&mutated),
                &obs,
                VerifyOptions::for_observation(&obs, slack),
            );
            if outcome.accepted() {
                pairs.push((first, second));
            }
        }
    }

    if pairs.is_empty() {
        println!("          no pair of mutations removes it either: the rejection does not rest on any one or two clauses");
        return ExitCode::SUCCESS;
    }

    println!(
        "          the rejection is over-determined: {} pair(s) of clauses must both be relaxed",
        pairs.len()
    );
    println!("MINIMAL RELAXATION");
    for (first, second) in pairs.iter().take(5) {
        println!("  {}", first.id);
        println!("  {}", second.id);
        println!("    -> {}", first.description);
        println!("    -> {}", second.description);
    }
    ExitCode::SUCCESS
}

fn run_ingest(bundle: PathBuf, map: PathBuf, out: Option<PathBuf>) -> ExitCode {
    let map = match adapters::load_map(&map) {
        Ok(m) => m,
        Err(e) => return fail(&e.to_string()),
    };
    let bundle = match adapters::load_bundle(&bundle) {
        Ok(b) => b,
        Err(e) => return fail(&e.to_string()),
    };
    let obs = adapters::normalize(&bundle, &map);
    if let Err(e) = obs.validate() {
        return fail(&e.to_string());
    }
    let body = match serde_json::to_string_pretty(&obs) {
        Ok(b) => b,
        Err(e) => return fail(&e.to_string()),
    };
    match out {
        Some(path) => {
            if let Err(e) = std::fs::write(&path, body) {
                return fail(&e.to_string());
            }
            let steps = obs.step_records().len();
            println!("RUN       {}", obs.run_id);
            println!(
                "PLANES    {}",
                obs.planes.keys().cloned().collect::<Vec<String>>().join(", ")
            );
            println!(
                "RECORDS   {} ({} with a declared step, {} effect-only)",
                obs.records.len(),
                steps,
                obs.records.len() - steps
            );
            println!("EDGES     {}", obs.edges.len());
            println!("WROTE     {}", path.display());
        }
        None => println!("{}", body),
    }
    ExitCode::SUCCESS
}

fn run_check(path: PathBuf) -> ExitCode {
    let raw = match std::fs::read_to_string(&path) {
        Ok(r) => r,
        Err(e) => return fail(&e.to_string()),
    };
    let signed: SignedCertificate = match serde_json::from_str(&raw) {
        Ok(s) => s,
        Err(e) => return fail(&e.to_string()),
    };
    match verify_signature(&signed) {
        Ok(()) => {
            println!("SIGNATURE VALID");
            println!("KEY       {}", signed.public_key);
            println!("PAYLOAD   sha256:{}", signed.payload_sha256);
            println!("VERDICT   {}", signed.certificate.verdict.to_uppercase());
            println!("WORKFLOW  {}", signed.certificate.workflow);
            println!("SPEC      {}", signed.certificate.spec_hash);
            println!("RUN       {}", signed.certificate.run_id);
            ExitCode::SUCCESS
        }
        Err(e) => fail(&e.to_string()),
    }
}

fn fail(message: &str) -> ExitCode {
    eprintln!("error: {}", message);
    ExitCode::from(2)
}
