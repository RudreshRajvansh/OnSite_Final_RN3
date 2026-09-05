use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    response::IntoResponse,
    routing::{get, post},
    Json, Router,
};
use engine::{permissiveness, verify, Net, Observation, VerifyOptions};
use serde_json::{json, Value};
use std::{collections::HashMap, net::SocketAddr, path::PathBuf, sync::Arc};
use tower_http::{cors::CorsLayer, services::ServeDir};

struct AppState {
    loaded: wsl::LoadedSpec,
    net: Net,
    fixtures: PathBuf,
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

fn slack_of(params: &HashMap<String, String>) -> usize {
    params
        .get("slack")
        .and_then(|s| s.parse().ok())
        .unwrap_or(0)
}

fn evaluate(state: &AppState, obs: &Observation, slack: usize) -> Value {
    let outcome = verify(&state.net, obs, VerifyOptions::for_observation(obs, slack));
    let robust = if outcome.accepted() {
        None
    } else {
        let mut wide = VerifyOptions::for_observation(obs, obs.records.len() + 4);
        wide.max_states = 400_000;
        Some(!verify(&state.net, obs, wide).accepted())
    };
    let certificate = explain::explain(
        &state.net,
        &state.loaded.spec.workflow,
        &state.loaded.hash,
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
    let path = state.fixtures.join(format!("{}.json", id));
    let obs = match Observation::load(&path) {
        Ok(o) => o,
        Err(e) => return not_found(e.to_string()).into_response(),
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
    let path = state.fixtures.join(format!("{}.json", id));
    let obs = match Observation::load(&path) {
        Ok(o) => o,
        Err(e) => return not_found(e.to_string()).into_response(),
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
    let state: Shared = Arc::new(AppState {
        loaded,
        net,
        fixtures: PathBuf::from(env_or("MASKEDRUNNER_FIXTURES", "fixtures")),
    });

    let app = Router::new()
        .route("/api/spec", get(get_spec))
        .route("/api/runs", get(get_runs))
        .route("/api/runs/:id", get(get_run))
        .route("/api/runs/:id/certificate", get(get_run_certificate))
        .route("/api/permissiveness", get(get_permissiveness))
        .route("/api/verify", post(post_verify))
        .route("/api/ingest", post(post_ingest))
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
