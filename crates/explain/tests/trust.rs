use explain::{check_trusted, sign, verify_signature, Certificate, CERTIFICATE_KIND};
use std::collections::BTreeSet;

fn certificate(run: &str, attests: &[&str]) -> Certificate {
    Certificate {
        kind: CERTIFICATE_KIND.to_string(),
        engine: "test".to_string(),
        workflow: "release-pipeline".to_string(),
        spec_hash: "sha256:00".to_string(),
        run_id: run.to_string(),
        observation_hash: "sha256:00".to_string(),
        verdict: "accept".to_string(),
        bound: 4,
        slack: 0,
        robust: None,
        states_explored: 5,
        witness: None,
        minimal_unsatisfiable_set: Vec::new(),
        mus_minimal: true,
        mus_oracle_calls: 0,
        failed_obligations: Vec::new(),
        notes: Vec::new(),
        attested_digests: attests.iter().map(|d| d.to_string()).collect(),
        issued_at_unix: 0,
    }
}

#[test]
fn a_valid_signature_is_not_by_itself_a_reason_to_believe_a_certificate() {
    // Anyone can generate a keypair and sign whatever they like. The signature
    // proves the document was not edited after signing; it says nothing about
    // who wrote it. Once certificates became an input, that distinction is the
    // whole security boundary.
    let forged = sign(certificate("attacker-run", &["sha256:DEAD"])).expect("signing works");
    assert!(
        verify_signature(&forged).is_ok(),
        "a self-signed forgery still has an internally valid signature"
    );

    let defender: BTreeSet<String> = ["1234".to_string()].into_iter().collect();
    assert!(
        check_trusted(&forged, &defender).is_err(),
        "a certificate from an unknown issuer must not be believed"
    );
}

#[test]
fn an_empty_trust_anchor_believes_nothing() {
    let real = sign(certificate("some-run", &["sha256:AA11"])).expect("signing works");
    assert!(
        check_trusted(&real, &BTreeSet::new()).is_err(),
        "with no configured issuer the verifier must fail closed, not open"
    );
}

#[test]
fn a_certificate_from_a_trusted_issuer_is_believed() {
    let real = sign(certificate("some-run", &["sha256:AA11"])).expect("signing works");
    let trusted: BTreeSet<String> = [real.public_key.clone()].into_iter().collect();
    assert!(check_trusted(&real, &trusted).is_ok());
}

#[test]
fn issuer_matching_ignores_hex_case() {
    let real = sign(certificate("some-run", &["sha256:AA11"])).expect("signing works");
    let trusted: BTreeSet<String> = [real.public_key.to_uppercase()].into_iter().collect();
    assert!(
        check_trusted(&real, &trusted).is_err(),
        "the anchor stores lowercase; an uppercase entry reaching the set directly is a miss"
    );
    let normalized: BTreeSet<String> = [real.public_key.to_lowercase()].into_iter().collect();
    assert!(check_trusted(&real, &normalized).is_ok());
}
