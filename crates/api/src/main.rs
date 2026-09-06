mod policy;

use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    response::IntoResponse,
    routing::{get, post},
    Json, Router,
};
use engine::{permissiveness, verify, Net, Observation, VerifyOptions};
use serde_json::{json, Value};
use std::{collections::HashMap, net::SocketAddr, path::PathBuf, sync::{Arc, RwLock}};
use tower_http::{cors::CorsLayer, services::ServeDir};

struct SpecEntry {
    loaded: wsl::LoadedSpec,
    net: Net,
    map: Option<adapters::AdapterMap>,
}

struct AppState {
    loaded: wsl::LoadedSpec,
    net: Net,
    fixtures: PathBuf,
    specs: RwLock<HashMap<String, SpecEntry>>,
    map: adapters::AdapterMap,
    policy: policy::BotPolicy,
}

type Shared = Arc<AppState>;

fn env_or(key: &str, fallback: &str) -> String {
    std::env::var(key).unwrap_or_else(|_| fallback.to_string())
}

fn bad_request(message: String) -> (StatusCode, Json<Value>) {
    (StatusCode::BAD_REQUEST, Json(json!({ "error": message })))
}

fn not_found(message: String) -> (StatusCode, Json<Value>) {
    (StatusCode::NOT_FOUND, Json(json!({ "error": message })))
}

/// Run ids address files under the fixtures directory, so they must not be able
/// to escape it. Anything outside this alphabet is rejected before it reaches
/// the filesystem, and errors never echo a path back to the caller.
fn safe_id(id: &str) -> Option<&str> {
    let ok = !id.is_empty()
        && id.len() <= 128
        && id != "."
        && id != ".."
        && id
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.')
        && !id.contains("..");
    ok.then_some(id)
}

fn slack_of(params: &HashMap<String, String>) -> usize {
    params
        .get("slack")
        .and_then(|s| s.parse().ok())
        .unwrap_or(0)
}

fn evaluate(state: &AppState, obs: &Observation, slack: usize) -> Value {
    let mut v = evaluate_with(&state.loaded, &state.net, obs, slack);
    let (allowed, findings) = policy::evaluate(&state.policy, obs);
    v["permission"] = json!({ "allowed": allowed, "findings": findings });
    v
}

fn evaluate_with(loaded: &wsl::LoadedSpec, net: &Net, obs: &Observation, slack: usize) -> Value {
    let outcome = verify(net, obs, VerifyOptions::for_observation(obs, slack));
    let robust = if outcome.accepted() {
        None
    } else {
        let mut wide = VerifyOptions::for_observation(obs, obs.records.len() + 4);
        wide.max_states = 400_000;
        Some(!verify(net, obs, wide).accepted())
    };
    let certificate = explain::explain(
        net,
        &loaded.spec.workflow,
        &loaded.hash,
        obs,
        &outcome,
        robust,
    );
    json!({
        "observation": obs,
        "outcome": outcome,
        "certificate": certificate,
        "robust": robust,
    })
}

async fn get_spec(State(state): State<Shared>) -> Json<Value> {
    Json(json!({
        "workflow": state.loaded.spec.workflow,
        "hash": state.loaded.hash,
        "short": state.loaded.short_hash(),
        "sound": state.loaded.report.is_sound(),
        "spec": state.loaded.spec,
        "diagnostics": state
            .loaded
            .report
            .diagnostics
            .iter()
            .map(|d| json!({
                "severity": format!("{:?}", d.severity).to_lowercase(),
                "code": d.code,
                "message": d.message,
            }))
            .collect::<Vec<Value>>(),
    }))
}

fn fixture_ids(state: &AppState) -> Vec<String> {
    let mut out = Vec::new();
    let Ok(entries) = std::fs::read_dir(&state.fixtures) else {
        return out;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) != Some("json") {
            continue;
        }
        if let Some(stem) = path.file_stem().and_then(|s| s.to_str()) {
            out.push(stem.to_string());
        }
    }
    out.sort();
    out
}

async fn get_runs(State(state): State<Shared>) -> Json<Value> {
    let runs: Vec<Value> = fixture_ids(&state)
        .into_iter()
        .filter_map(|id| {
            let obs = Observation::load(state.fixtures.join(format!("{}.json", id))).ok()?;
            Some(json!({
                "id": id,
                "run_id": obs.run_id,
                "records": obs.records.len(),
                "effects": obs.effects().count(),
                "edges": obs.edges.len(),
                "planes": obs.planes.keys().cloned().collect::<Vec<String>>(),
            }))
        })
        .collect();
    Json(json!({ "runs": runs }))
}

async fn get_run(
    State(state): State<Shared>,
    Path(id): Path<String>,
    Query(params): Query<HashMap<String, String>>,
) -> impl IntoResponse {
    let Some(id) = safe_id(&id) else {
        return not_found("no such run".into()).into_response();
    };
    let path = state.fixtures.join(format!("{}.json", id));
    let obs = match Observation::load(&path) {
        Ok(o) => o,
        Err(_) => return not_found("no such run".into()).into_response(),
    };
    let mut body = evaluate(&state, &obs, slack_of(&params));
    body["id"] = json!(id);
    Json(body).into_response()
}

async fn get_run_certificate(
    State(state): State<Shared>,
    Path(id): Path<String>,
    Query(params): Query<HashMap<String, String>>,
) -> impl IntoResponse {
    let Some(id) = safe_id(&id) else {
        return not_found("no such run".into()).into_response();
    };
    let path = state.fixtures.join(format!("{}.json", id));
    let obs = match Observation::load(&path) {
        Ok(o) => o,
        Err(_) => return not_found("no such run".into()).into_response(),
    };
    let slack = slack_of(&params);
    let outcome = verify(&state.net, &obs, VerifyOptions::for_observation(&obs, slack));
    let robust = if outcome.accepted() {
        None
    } else {
        let mut wide = VerifyOptions::for_observation(&obs, obs.records.len() + 4);
        wide.max_states = 400_000;
        Some(!verify(&state.net, &obs, wide).accepted())
    };
    let certificate = explain::explain(
        &state.net,
        &state.loaded.spec.workflow,
        &state.loaded.hash,
        &obs,
        &outcome,
        robust,
    );
    match explain::sign(certificate) {
        Ok(signed) => Json(json!(signed)).into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "error": e.to_string() })),
        )
            .into_response(),
    }
}

async fn post_verify(
    State(state): State<Shared>,
    Query(params): Query<HashMap<String, String>>,
    Json(body): Json<Observation>,
) -> impl IntoResponse {
    if let Err(e) = body.validate() {
        return bad_request(e.to_string()).into_response();
    }
    Json(evaluate(&state, &body, slack_of(&params))).into_response()
}

async fn post_ingest(
    State(state): State<Shared>,
    Query(params): Query<HashMap<String, String>>,
    body: String,
) -> impl IntoResponse {
    let bundle: adapters::Bundle = match serde_json::from_str(&body) {
        Ok(b) => b,
        Err(e) => return bad_request(e.to_string()).into_response(),
    };
    let map = match adapters::load_map(env_or("MASKEDRUNNER_MAP", "spec/adapter.map.json")) {
        Ok(m) => m,
        Err(e) => return bad_request(e.to_string()).into_response(),
    };
    let obs = adapters::normalize(&bundle, &map);
    if let Err(e) = obs.validate() {
        return bad_request(e.to_string()).into_response();
    }
    Json(evaluate(&state, &obs, slack_of(&params))).into_response()
}

#[derive(serde::Deserialize)]
struct LivePayload {
    run: serde_json::Value,
    jobs: serde_json::Value,
    #[serde(default)]
    facts: serde_json::Value,
    #[serde(default)]
    spec: Option<String>,
    #[serde(default)]
    slack: Option<usize>,
    #[serde(default)]
    tamper: Option<TamperOp>,
}

#[derive(serde::Deserialize)]
struct TamperOp {
    step: String,
    digest: String,
}

#[derive(serde::Deserialize)]
struct OnboardPayload {
    name: String,
    workflow: String,
}

async fn post_onboard(
    State(state): State<Shared>,
    Json(payload): Json<OnboardPayload>,
) -> impl IntoResponse {
    let wf: wsl::generate::Workflow = match serde_yaml::from_str(&payload.workflow) {
        Ok(w) => w,
        Err(e) => return bad_request(format!("not a workflow file: {}", e)).into_response(),
    };
    let spec_yaml = wsl::generate::generate(&wf);
    let loaded = match wsl::parse_str(&spec_yaml) {
        Ok(l) => l,
        Err(e) => return bad_request(format!("generated spec failed to parse: {}", e)).into_response(),
    };
    let sound = loaded.report.is_sound();
    let jobs = wf.jobs.len();
    let transitions = loaded.spec.transitions.len();
    let diagnostics: Vec<String> = loaded
        .report
        .diagnostics
        .iter()
        .map(|d| format!("{} {}", d.code, d.message))
        .collect();
    let key = payload.name.clone();
    if key.is_empty() || key.len() > 200 {
        return bad_request("spec name must be 1..200 characters".into()).into_response();
    }
    if sound {
        // Derive an adapter map from this workflow's own job names, so the
        // repository's runs resolve even when its jobs are named nothing like
        // the built-in vocabulary.
        let mut jobs_map: std::collections::BTreeMap<String, adapters::StepRule> =
            std::collections::BTreeMap::new();
        for (job_name, job) in &wf.jobs {
            let transition = wsl::generate::slug(job_name);
            let effects = match wsl::generate::guess_effect(job) {
                Some("artifact_create") => vec![adapters::EffectRule {
                    kind: "artifact_create".into(),
                    args: [("digest".to_string(), "${outputs.digest}".to_string())].into(),
                }],
                Some("registry_write") => vec![adapters::EffectRule {
                    kind: "registry_write".into(),
                    args: [
                        ("scope".to_string(), "registry://prod/${repository_name}".to_string()),
                        ("digest".to_string(), "${outputs.digest}".to_string()),
                    ].into(),
                }],
                Some("ci_report") => vec![adapters::EffectRule {
                    kind: "ci_report".into(),
                    args: [("digest".to_string(), "${outputs.digest}".to_string())].into(),
                }],
                Some("vcs_read") => vec![adapters::EffectRule {
                    kind: "vcs_read".into(),
                    args: [("scope".to_string(), "repo/${repository_name}".to_string())].into(),
                }],
                _ => vec![],
            };
            jobs_map.insert(job_name.clone(), adapters::StepRule { step: transition, effects });
        }
        let mut repo_map = state.map.clone();
        repo_map.jobs = jobs_map;

        let net = Net::compile(&loaded.spec);
        let mut specs = state.specs.write().unwrap();
        // Onboarding is unauthenticated in this build, so the registry is capped
        // rather than allowed to grow without bound.
        if specs.len() >= 256 && !specs.contains_key(&key) {
            drop(specs);
            return bad_request("spec registry is full".into()).into_response();
        }
        specs.insert(key.clone(), SpecEntry { loaded, net, map: Some(repo_map) });
    }
    Json(json!({
        "name": key,
        "registered": sound,
        "sound": sound,
        "jobs": jobs,
        "transitions": transitions,
        "spec_yaml": spec_yaml,
        "diagnostics": diagnostics,
    }))
    .into_response()
}

async fn post_live(
    State(state): State<Shared>,
    Json(payload): Json<LivePayload>,
) -> impl IntoResponse {
    let run: adapters::github::Run = match serde_json::from_value(payload.run) {
        Ok(r) => r,
        Err(e) => return bad_request(format!("run: {}", e)).into_response(),
    };
    let jobs: adapters::github::Jobs = match serde_json::from_value(payload.jobs) {
        Ok(j) => j,
        Err(e) => return bad_request(format!("jobs: {}", e)).into_response(),
    };
    let mut facts: Vec<adapters::github::Fact> = if payload.facts.is_null() {
        Vec::new()
    } else {
        match serde_json::from_value(payload.facts) {
            Ok(f) => f,
            Err(e) => return bad_request(format!("facts: {}", e)).into_response(),
        }
    };
    // Optional live tamper: rewrite one step's published digest, so the demo can
    // flip a genuine run into an attack without editing files.
    if let Some(t) = &payload.tamper {
        for f in facts.iter_mut() {
            if f.step == t.step {
                f.digest = Some(t.digest.clone());
                f.provenance = None;
            }
        }
    }

    // If the caller named an onboarded spec, normalize with that repo's own map.
    let repo_map = payload
        .spec
        .as_ref()
        .and_then(|n| state.specs.read().unwrap().get(n).and_then(|e| e.map.clone()));
    let obs = adapters::github::normalize(
        &run,
        &jobs,
        &facts,
        repo_map.as_ref().unwrap_or(&state.map),
    );
    if let Err(e) = obs.validate() {
        return bad_request(e.to_string()).into_response();
    }
    // Refuse to give a verdict when nothing in the run could be mapped to the
    // model. Accepting an observation we did not understand is the worst
    // possible failure for a verifier.
    if obs.step_records().is_empty() {
        return Json(json!({
            "unverifiable": true,
            "reason": format!(
                "None of the {} job(s) in this run map to a transition in any known spec.                  Onboard this repository first, or its jobs use names the model does not declare                  (reusable workflows report jobs as \"caller / inner job\").",
                jobs.jobs.len()
            ),
            "observation": obs,
            "jobs_seen": jobs.jobs.iter().map(|j| j.name.clone()).collect::<Vec<String>>(),
        }))
        .into_response();
    }

    let specs = state.specs.read().unwrap();
    let chosen: &SpecEntry = if let Some(e) = payload.spec.as_ref().and_then(|n| specs.get(n)) {
        e
    } else {
        let steps: std::collections::BTreeSet<String> =
            obs.records.iter().filter_map(|r| r.step.clone()).collect();
        let mut best: Option<(&SpecEntry, isize)> = None;
        for entry in specs.values() {
            let ids: std::collections::BTreeSet<&str> =
                entry.loaded.spec.transitions.iter().map(|t| t.id.as_str()).collect();
            let covered = steps.iter().filter(|s| ids.contains(s.as_str())).count();
            if covered == 0 { continue; }
            let extra = ids.len().saturating_sub(covered);
            let score = covered as isize * 10 - extra as isize;
            if best.map(|(_, b)| score > b).unwrap_or(true) { best = Some((entry, score)); }
        }
        match best {
            Some((e, _)) => e,
            None => specs.get("release").or_else(|| specs.values().next())
                .expect("at least one spec must be loaded"),
        }
    };
    let loaded = &chosen.loaded;
    let net = &chosen.net;
    let slack = payload.slack.unwrap_or(1);
    let mut body = evaluate_with(loaded, net, &obs, slack);
    let (allowed, findings) = policy::evaluate(&state.policy, &obs);
    body["permission"] = json!({ "allowed": allowed, "findings": findings });
    body["id"] = json!(obs.run_id);
    body["spec_used"] = json!(loaded.spec.workflow);
    body["spec_def"] = json!(loaded.spec);
    Json(body).into_response()
}

async fn get_permissiveness(
    State(state): State<Shared>,
    Query(params): Query<HashMap<String, String>>,
) -> Json<Value> {
    let depth: usize = params
        .get("depth")
        .and_then(|d| d.parse().ok())
        .unwrap_or(8)
        .min(12);
    let budget: usize = params
        .get("budget")
        .and_then(|b| b.parse().ok())
        .unwrap_or(400_000);
    let mut rows = Vec::new();
    for level in 1..=depth {
        let measured = permissiveness(&state.net, level, 200_000, budget);
        let truncated = measured.truncated;
        rows.push(json!({
            "depth": level,
            "shapes": measured.shapes,
            "states": measured.states,
            "truncated": truncated,
        }));
        if truncated {
            break;
        }
    }
    Json(json!({ "rows": rows }))
}

#[tokio::main]
async fn main() {
    let spec_path = env_or("MASKEDRUNNER_SPEC", "spec/release.wsl.yaml");
    let loaded = match wsl::load_checked(&spec_path) {
        Ok(l) => l,
        Err(e) => {
            eprintln!("error: {}", e);
            std::process::exit(2);
        }
    };
    let net = Net::compile(&loaded.spec);
    // Every sound spec in the spec directory is available to verify against.
    let spec_dir = PathBuf::from(env_or("MASKEDRUNNER_SPECS", "spec"));
    let mut specs: HashMap<String, SpecEntry> = HashMap::new();
    if let Ok(entries) = std::fs::read_dir(&spec_dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if !path.to_string_lossy().ends_with(".wsl.yaml") {
                continue;
            }
            let Some(name) = path
                .file_name()
                .and_then(|f| f.to_str())
                .map(|f| f.trim_end_matches(".wsl.yaml").to_string())
            else {
                continue;
            };
            match wsl::load_checked(&path) {
                Ok(l) => {
                    let n = Net::compile(&l.spec);
                    specs.insert(name, SpecEntry { loaded: l, net: n, map: None });
                }
                Err(e) => eprintln!("skipping unsound spec {}: {}", path.display(), e),
            }
        }
    }
    if specs.is_empty() {
        eprintln!("error: no sound spec found in {}", spec_dir.display());
        std::process::exit(2);
    }
    eprintln!(
        "loaded {} spec(s): {}",
        specs.len(),
        specs.keys().cloned().collect::<Vec<_>>().join(", ")
    );
    let map = adapters::load_map("spec/live.map.json")
        .or_else(|_| adapters::load_map("spec/gha.map.json"))
        .or_else(|_| adapters::load_map("spec/adapter.map.json"))
        .unwrap_or_default();

    let policy = policy::load(env_or("MASKEDRUNNER_POLICY", "demo/bot-policy.json"))
        .unwrap_or(policy::BotPolicy {
            identity: String::new(),
            allowed_actions: vec![
                "vcs_read".into(), "artifact_create".into(), "ci_report".into(),
                "secret_read".into(), "registry_write".into(),
            ],
            allowed_scopes: vec!["repo/*".into(), "secrets://prod/*".into(), "registry://prod/*".into()],
        });

    let state: Shared = Arc::new(AppState {
        loaded,
        net,
        fixtures: PathBuf::from(env_or("MASKEDRUNNER_FIXTURES", "fixtures")),
        specs: RwLock::new(specs),
        map,
        policy,
    });

    let app = Router::new()
        .route("/api/spec", get(get_spec))
        .route("/api/runs", get(get_runs))
        .route("/api/runs/:id", get(get_run))
        .route("/api/runs/:id/certificate", get(get_run_certificate))
        .route("/api/permissiveness", get(get_permissiveness))
        .route("/api/verify", post(post_verify))
        .route("/api/ingest", post(post_ingest))
        .route("/api/live", post(post_live))
        .route("/api/onboard", post(post_onboard))
        .layer(axum::extract::DefaultBodyLimit::max(4 * 1024 * 1024))
        .layer(CorsLayer::permissive())
        .fallback_service(ServeDir::new(env_or("MASKEDRUNNER_WEB", "web")))
        .with_state(state);

    let addr: SocketAddr = env_or("MASKEDRUNNER_ADDR", "127.0.0.1:8787")
        .parse()
        .expect("MASKEDRUNNER_ADDR must be host:port");
    let listener = match tokio::net::TcpListener::bind(addr).await {
        Ok(l) => l,
        Err(e) => {
            eprintln!("error: cannot bind {}: {}", addr, e);
            std::process::exit(2);
        }
    };
    println!("maskedrunner listening on http://{}", addr);
    axum::serve(listener, app).await.expect("server failed");
}
