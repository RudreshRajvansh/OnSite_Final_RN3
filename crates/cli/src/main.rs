mod policy;

use clap::{Parser, Subcommand};
use engine::{permissiveness, verify, Net, Observation, VerifyOptions, VerifyOutcome};
use explain::{explain, sign, verify_signature, Certificate, SignedCertificate};
use std::path::PathBuf;
use std::process::ExitCode;

const DEFAULT_SPEC: &str = "spec/release.wsl.yaml";
const DEFAULT_MAP: &str = "spec/adapter.map.json";
const DEFAULT_POLICY: &str = "demo/bot-policy.json";

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
        #[arg(long)]
        evidence: Vec<PathBuf>,
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
    IngestActions {
        #[arg(long)]
        run: PathBuf,
        #[arg(long)]
        jobs: PathBuf,
        #[arg(long)]
        facts: Option<PathBuf>,
        #[arg(long, default_value = DEFAULT_MAP)]
        map: PathBuf,
        #[arg(long)]
        out: Option<PathBuf>,
    },
    Generate {
        #[arg(long)]
        workflow: PathBuf,
        #[arg(long)]
        out: Option<PathBuf>,
    },
    Scenario {
        #[arg(long, default_value = DEFAULT_SPEC)]
        spec: PathBuf,
        #[arg(long, default_value = DEFAULT_MAP)]
        map: PathBuf,
        #[arg(long, default_value = DEFAULT_POLICY)]
        policy: PathBuf,
        #[arg(long, default_value = "fixtures/raw/bot-legit.json")]
        legit: PathBuf,
        #[arg(long, default_value = "fixtures/raw/bot-stolen.json")]
        stolen: PathBuf,
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
            evidence,
        } => run_verify(spec, observation, slack, json, certificate, evidence),
        Command::Permissiveness {
            spec,
            depth,
            cap,
            budget,
        } => run_permissiveness(spec, depth, cap, budget),
        Command::Check { certificate } => run_check(certificate),
        Command::Ingest { bundle, map, out } => run_ingest(bundle, map, out),
        Command::IngestActions { run, jobs, facts, map, out } => {
            run_ingest_actions(run, jobs, facts, map, out)
        }
        Command::Generate { workflow, out } => run_generate(workflow, out),
        Command::Scenario { spec, map, policy, legit, stolen } => {
            run_scenario(spec, map, policy, legit, stolen)
        }
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

struct PresentedEvidence {
    run_id: String,
    digests: Vec<String>,
}

fn load_evidence(path: &PathBuf, workflow: &str) -> Result<PresentedEvidence, String> {
    let body = std::fs::read_to_string(path).map_err(|e| format!("{}: {}", path.display(), e))?;
    let signed: SignedCertificate =
        serde_json::from_str(&body).map_err(|e| format!("{}: {}", path.display(), e))?;

    verify_signature(&signed).map_err(|e| format!("{}: {}", path.display(), e))?;

    let recomputed = signed
        .certificate
        .payload_hash()
        .map_err(|e| format!("{}: {}", path.display(), e))?;
    if recomputed != signed.payload_sha256 {
        return Err(format!(
            "{}: payload hash does not match the signed body",
            path.display()
        ));
    }
    if signed.certificate.verdict != "accept" {
        return Err(format!(
            "{}: certificate records a `{}` verdict, so it attests nothing",
            path.display(),
            signed.certificate.verdict
        ));
    }
    if signed.certificate.workflow != workflow {
        return Err(format!(
            "{}: certificate is for workflow `{}`, not `{}`",
            path.display(),
            signed.certificate.workflow,
            workflow
        ));
    }
    if signed.certificate.attested_digests.is_empty() {
        return Err(format!(
            "{}: certificate attests no artifact digest",
            path.display()
        ));
    }
    Ok(PresentedEvidence {
        run_id: signed.certificate.run_id.clone(),
        digests: signed.certificate.attested_digests,
    })
}

fn run_verify(
    spec: PathBuf,
    observation: PathBuf,
    slack: usize,
    json: bool,
    certificate: Option<PathBuf>,
    evidence: Vec<PathBuf>,
) -> ExitCode {
    let loaded = match wsl::load_checked(&spec) {
        Ok(l) => l,
        Err(e) => return fail(&e.to_string()),
    };
    let obs = match Observation::load(&observation) {
        Ok(o) => o,
        Err(e) => return fail(&e.to_string()),
    };
    let mut net = Net::compile(&loaded.spec);

    for path in &evidence {
        match load_evidence(path, &loaded.spec.workflow) {
            Ok(presented) => {
                if !json {
                    println!(
                        "EVIDENCE  {} attests {} [{}]",
                        presented.run_id,
                        presented.digests.join(", "),
                        path.display()
                    );
                }
                net.present_evidence(presented.digests);
            }
            Err(e) => return fail(&e),
        }
    }

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
    if outcome.witness.is_none() && !outcome.explained.is_empty() {
        println!(
            "EXPLAINED {}      {} of {} observed steps",
            outcome.explained_path(),
            outcome.explained.iter().filter(|s| s.observed).count(),
            outcome.observed_steps
        );
        for step in &outcome.explained {
            print_step(step);
        }
    }
    if let Some(blocked) = &outcome.blocked {
        println!(
            "BLOCKED   {:<26} {:<20} [{}]",
            blocked.step, blocked.principal, blocked.record
        );
    }
    if let Some(witness) = &outcome.witness {
        println!("WITNESS   {}", outcome.witness_path());
        for step in witness {
            print_step(step);
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

fn print_step(step: &engine::WitnessStep) {
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
        println!("Mutation testing only applies to a rejected run. This one is accepted.");
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

fn scenario_leg(
    title: &str,
    story: &str,
    bundle: &PathBuf,
    map: &adapters::AdapterMap,
    policy: &policy::BotPolicy,
    net: &Net,
    slack: usize,
) -> Option<bool> {
    // Accept either a ready observation or a raw three-plane bundle.
    let obs = match Observation::load(bundle) {
        Ok(o) => o,
        Err(_) => match adapters::load_bundle(bundle) {
            Ok(b) => adapters::normalize(&b, map),
            Err(e) => {
                eprintln!("error: {}", e);
                return None;
            }
        },
    };
    println!();
    println!("== {} ==", title);
    println!("   {}", story);
    println!();

    let policy_outcome = policy::evaluate(policy, &obs);
    println!(
        "   IDENTITY AND PERMISSION CHECK   {} identities, {} actions",
        policy_outcome.checked_identities, policy_outcome.checked_actions
    );
    if policy_outcome.allowed() {
        println!("   -> ALLOWED. Every action is one this identity may perform.");
    } else {
        println!("   -> DENIED");
        for f in &policy_outcome.findings {
            println!("      {}  {}", f.subject, f.detail);
        }
    }

    let options = VerifyOptions::for_observation(&obs, slack);
    let outcome = verify(net, &obs, options);
    println!();
    println!("   REACHABILITY CHECK   (one unlogged step allowed)");
    if outcome.accepted() {
        println!("   -> ACCEPT. {}", outcome.witness_path());
    } else {
        println!("   -> REJECT");
        if !outcome.explained.is_empty() {
            println!("      legal so far: {}", outcome.explained_path());
        }
        if let Some(b) = &outcome.blocked {
            println!("      blocked at:   {}", b.step);
        }
        for f in outcome.failures.iter().take(2) {
            println!("      {}", f.render());
        }
    }
    Some(outcome.accepted())
}

fn run_generate(workflow: PathBuf, out: Option<PathBuf>) -> ExitCode {
    let raw = match std::fs::read_to_string(&workflow) {
        Ok(r) => r,
        Err(e) => return fail(&e.to_string()),
    };
    let wf: wsl::generate::Workflow = match serde_yaml::from_str(&raw) {
        Ok(w) => w,
        Err(e) => return fail(&format!("not a GitHub Actions workflow: {}", e)),
    };
    let spec = wsl::generate::generate(&wf);
    match out {
        Some(path) => {
            if let Err(e) = std::fs::write(&path, &spec) {
                return fail(&e.to_string());
            }
            let jobs = wf.jobs.len();
            eprintln!("GENERATED {} from {} job(s)", path.display(), jobs);
            eprintln!("Now edit the TODO lines, then: maskedrunner lint --spec {}", path.display());
        }
        None => print!("{}", spec),
    }
    ExitCode::SUCCESS
}

fn run_scenario(
    spec: PathBuf,
    map: PathBuf,
    policy_path: PathBuf,
    legit: PathBuf,
    stolen: PathBuf,
) -> ExitCode {
    let loaded = match wsl::load_checked(&spec) {
        Ok(l) => l,
        Err(e) => return fail(&e.to_string()),
    };
    let map = match adapters::load_map(&map) {
        Ok(m) => m,
        Err(e) => return fail(&e.to_string()),
    };
    let bot = match policy::load(&policy_path) {
        Ok(p) => p,
        Err(e) => return fail(&e),
    };
    let net = Net::compile(&loaded.spec);

    println!("SERVICE ACCOUNT");
    println!("   identity     {}", bot.identity);
    println!(
        "   credential   {} {}  issued {}",
        bot.credential.kind, bot.credential.id, bot.credential.issued
    );
    println!(
        "   rotated      {}",
        bot.credential.last_rotated.clone().unwrap_or_else(|| "never".to_string())
    );
    println!("   may perform  {}", bot.allowed_actions.join(", "));
    println!("   may write to {}", bot.allowed_scopes.join(", "));
    println!("   {}", bot.description);

    let a = scenario_leg(
        "1. The pipeline runs normally",
        "The service account runs its normal pipeline, start to finish.",
        &legit,
        &map,
        &bot,
        &net,
        1,
    );
    let b = scenario_leg(
        "2. The credential is stolen and used directly",
        "Same identity, same permissions. The stolen token does something the pipeline never does.",
        &stolen,
        &map,
        &bot,
        &net,
        1,
    );

    println!();
    match (a, b) {
        (Some(true), Some(false)) => {
            println!("The permission check passed both runs. It is answering a different question:");
            println!("may this identity do this? The answer is yes in both cases, because the");
            println!("credential is real. Reachability asks whether the outcome was producible.");
            ExitCode::SUCCESS
        }
        _ => {
            println!("Scenario did not produce the expected contrast; inspect the runs above.");
            ExitCode::from(1)
        }
    }
}

fn run_ingest_actions(
    run: PathBuf,
    jobs: PathBuf,
    facts: Option<PathBuf>,
    map: PathBuf,
    out: Option<PathBuf>,
) -> ExitCode {
    let map = match adapters::load_map(&map) {
        Ok(m) => m,
        Err(e) => return fail(&e.to_string()),
    };
    let run = match adapters::github::load_run(&run) {
        Ok(r) => r,
        Err(e) => return fail(&e.to_string()),
    };
    let jobs = match adapters::github::load_jobs(&jobs) {
        Ok(j) => j,
        Err(e) => return fail(&e.to_string()),
    };
    let facts = match facts {
        Some(path) => match adapters::github::load_facts(&path) {
            Ok(f) => f,
            Err(e) => return fail(&e.to_string()),
        },
        None => Vec::new(),
    };
    let obs = adapters::github::normalize(&run, &jobs, &facts, &map);
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
            println!("RUN       {}", obs.run_id);
            println!("SOURCE    GitHub Actions REST API");
            println!(
                "RECORDS   {} steps mapped to workflow transitions",
                obs.step_records().len()
            );
            println!("EDGES     {}", obs.edges.len());
            println!("WROTE     {}", path.display());
        }
        None => println!("{}", body),
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
