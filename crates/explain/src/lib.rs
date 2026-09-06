pub mod certificate;
pub mod mus;

pub use certificate::{
    check_trusted, public_key_of, sign, trust_anchor, verify_signature, Certificate,
    CertificateError, SignedCertificate, CERTIFICATE_KIND, SIGNING_KEY_ENV, TRUSTED_KEYS_ENV,
};
pub use mus::{extract, MusOptions, MusResult};

use engine::{Net, Observation, VerifyOutcome};

pub fn explain(
    net: &Net,
    workflow: &str,
    spec_hash: &str,
    obs: &Observation,
    outcome: &VerifyOutcome,
    robust: Option<bool>,
) -> Certificate {
    let mut notes = Vec::new();
    let mut core = MusResult {
        facts: Vec::new(),
        oracle_calls: 0,
        minimal: true,
        relaxation_accepts: false,
    };

    if !outcome.accepted() {
        core = extract(net, obs, MusOptions::for_observation(obs));
        if core.relaxation_accepts {
            let complete: Vec<String> = obs
                .planes
                .iter()
                .filter(|(_, p)| p.complete)
                .map(|(name, _)| name.clone())
                .collect();
            notes.push(format!(
                "this rejection holds only because plane(s) [{}] are declared complete. If any step may go unlogged, the observation is reachable",
                complete.join(", ")
            ));
        }
        if !core.minimal {
            notes.push(
                "the core could not be reduced to a locally minimal set within the oracle budget"
                    .to_string(),
            );
        }
    }

    if outcome.exhausted {
        notes.push(format!(
            "search stopped at the state cap; the result is relative to bound k={}",
            outcome.bound
        ));
    }

    let mut attested_digests: Vec<String> = Vec::new();
    if outcome.accepted() {
        let mut seen = std::collections::BTreeSet::new();
        for record in &obs.records {
            for effect in &record.effects {
                if let Some(digest) = effect.args.get("digest") {
                    if !digest.starts_with('~') && !digest.starts_with("<unresolved:") {
                        seen.insert(digest.clone());
                    }
                }
            }
        }
        attested_digests = seen.into_iter().collect();
    }

    Certificate {
        kind: CERTIFICATE_KIND.to_string(),
        engine: format!("maskedrunner {}", env!("CARGO_PKG_VERSION")),
        workflow: workflow.to_string(),
        spec_hash: format!("sha256:{}", spec_hash),
        run_id: obs.run_id.clone(),
        observation_hash: format!("sha256:{}", obs.hash()),
        verdict: if outcome.accepted() {
            "accept".to_string()
        } else {
            "reject".to_string()
        },
        bound: outcome.bound,
        slack: outcome.slack,
        robust,
        states_explored: outcome.states_explored,
        witness: outcome
            .witness
            .as_ref()
            .map(|w| w.iter().map(|s| s.transition.clone()).collect()),
        minimal_unsatisfiable_set: core.facts,
        mus_minimal: core.minimal,
        mus_oracle_calls: core.oracle_calls,
        failed_obligations: outcome.failures.iter().map(|f| f.render()).collect(),
        notes,
        attested_digests,
        issued_at_unix: certificate::now_unix(),
    }
}
