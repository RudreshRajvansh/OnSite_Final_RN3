use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use engine::Fact;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub const CERTIFICATE_KIND: &str = "maskedrunner.non-reachability-certificate/v1";
pub const SIGNING_KEY_ENV: &str = "MASKEDRUNNER_SIGNING_KEY";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Certificate {
    pub kind: String,
    pub engine: String,
    pub workflow: String,
    pub spec_hash: String,
    pub run_id: String,
    pub observation_hash: String,
    pub verdict: String,
    pub bound: usize,
    pub slack: usize,
    pub robust: Option<bool>,
    pub states_explored: usize,
    pub witness: Option<Vec<String>>,
    pub minimal_unsatisfiable_set: Vec<Fact>,
    pub mus_minimal: bool,
    pub mus_oracle_calls: usize,
    pub failed_obligations: Vec<String>,
    pub notes: Vec<String>,
    pub issued_at_unix: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedCertificate {
    pub certificate: Certificate,
    pub payload_sha256: String,
    pub public_key: String,
    pub signature: String,
}

#[derive(Debug)]
pub enum CertificateError {
    BadKey(String),
    BadSignature(String),
    Encoding(String),
}

impl std::fmt::Display for CertificateError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CertificateError::BadKey(m) => write!(f, "signing key is unusable: {}", m),
            CertificateError::BadSignature(m) => write!(f, "signature does not verify: {}", m),
            CertificateError::Encoding(m) => write!(f, "certificate encoding failed: {}", m),
        }
    }
}

impl std::error::Error for CertificateError {}

impl Certificate {
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, CertificateError> {
        serde_json::to_vec(self).map_err(|e| CertificateError::Encoding(e.to_string()))
    }

    pub fn payload_hash(&self) -> Result<String, CertificateError> {
        let bytes = self.canonical_bytes()?;
        let mut h = Sha256::new();
        h.update(&bytes);
        Ok(hex::encode(h.finalize()))
    }
}

pub fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

pub fn signing_key() -> Result<SigningKey, CertificateError> {
    match std::env::var(SIGNING_KEY_ENV) {
        Ok(raw) => {
            let bytes =
                hex::decode(raw.trim()).map_err(|e| CertificateError::BadKey(e.to_string()))?;
            let bytes: [u8; 32] = bytes.try_into().map_err(|_| {
                CertificateError::BadKey("expected 32 hex-encoded bytes".to_string())
            })?;
            Ok(SigningKey::from_bytes(&bytes))
        }
        Err(_) => {
            let mut bytes = [0u8; 32];
            rand::rngs::OsRng.fill_bytes(&mut bytes);
            Ok(SigningKey::from_bytes(&bytes))
        }
    }
}

pub fn sign(certificate: Certificate) -> Result<SignedCertificate, CertificateError> {
    let key = signing_key()?;
    let payload = certificate.canonical_bytes()?;
    let signature: Signature = key.sign(&payload);
    Ok(SignedCertificate {
        payload_sha256: certificate.payload_hash()?,
        certificate,
        public_key: hex::encode(key.verifying_key().to_bytes()),
        signature: hex::encode(signature.to_bytes()),
    })
}

pub fn verify_signature(signed: &SignedCertificate) -> Result<(), CertificateError> {
    let key_bytes = hex::decode(&signed.public_key)
        .map_err(|e| CertificateError::BadKey(e.to_string()))?;
    let key_bytes: [u8; 32] = key_bytes
        .try_into()
        .map_err(|_| CertificateError::BadKey("public key must be 32 bytes".to_string()))?;
    let key = VerifyingKey::from_bytes(&key_bytes)
        .map_err(|e| CertificateError::BadKey(e.to_string()))?;

    let signature_bytes = hex::decode(&signed.signature)
        .map_err(|e| CertificateError::BadSignature(e.to_string()))?;
    let signature_bytes: [u8; 64] = signature_bytes
        .try_into()
        .map_err(|_| CertificateError::BadSignature("signature must be 64 bytes".to_string()))?;
    let signature = Signature::from_bytes(&signature_bytes);

    let payload = signed.certificate.canonical_bytes()?;
    let digest = signed.certificate.payload_hash()?;
    if digest != signed.payload_sha256 {
        return Err(CertificateError::BadSignature(
            "payload hash does not match the certificate body".to_string(),
        ));
    }
    key.verify(&payload, &signature)
        .map_err(|e| CertificateError::BadSignature(e.to_string()))
}
