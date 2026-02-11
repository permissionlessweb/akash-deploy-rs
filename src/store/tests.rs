use super::*;
use crate::state::{DeploymentState, Step};

fn make_test_state() -> DeploymentState {
    let mut state = DeploymentState::new("test-session", "akash1owner")
        .with_label("my-deploy")
        .with_sdl("version: \"2.0\"");
    state.dseq = Some(12345);
    state.cert_pem =
        Some(b"-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----".to_vec());
    state.key_pem =
        Some(b"-----BEGIN PRIVATE KEY-----\nsecret\n-----END PRIVATE KEY-----".to_vec());
    state.transition(Step::Complete);
    state
}

#[test]
fn test_record_roundtrip() {
    let state = make_test_state();
    let password = "test-password-123";

    let record = DeploymentRecord::from_state(&state, password).unwrap();

    assert_eq!(record.dseq, 12345);
    assert_eq!(record.owner, "akash1owner");
    assert_eq!(record.label, "my-deploy");

    // cert_pem should be stored as-is
    assert_eq!(record.cert_pem, state.cert_pem);

    // key_pem should be encrypted (different from plaintext)
    assert!(record.encrypted_key_pem.is_some());
    assert_ne!(
        record.encrypted_key_pem.as_ref().unwrap(),
        state.key_pem.as_ref().unwrap()
    );

    // Roundtrip back to state
    let restored = record.to_state("new-session", password).unwrap();
    assert_eq!(restored.session_id, "new-session");
    assert_eq!(restored.dseq, Some(12345));
    assert_eq!(restored.owner, "akash1owner");
    assert_eq!(restored.label, "my-deploy");
    assert_eq!(restored.key_pem, state.key_pem);
    assert_eq!(restored.cert_pem, state.cert_pem);
    assert!(matches!(restored.step, Step::Complete));
}

#[test]
fn test_record_wrong_password_fails() {
    let state = make_test_state();
    let record = DeploymentRecord::from_state(&state, "correct").unwrap();
    let result = record.to_state("s", "wrong");
    assert!(result.is_err());
}

#[test]
fn test_record_no_dseq_fails() {
    let state = DeploymentState::new("s", "akash1owner");
    assert!(state.dseq.is_none());
    let result = DeploymentRecord::from_state(&state, "pw");
    assert!(result.is_err());
}

#[test]
fn test_record_none_key() {
    let mut state = make_test_state();
    state.key_pem = None;

    let record = DeploymentRecord::from_state(&state, "pw").unwrap();
    assert!(record.encrypted_key_pem.is_none());

    let restored = record.to_state("s", "pw").unwrap();
    assert!(restored.key_pem.is_none());
}

#[test]
fn test_record_serialization() {
    let state = make_test_state();
    let record = DeploymentRecord::from_state(&state, "pw").unwrap();

    let json = serde_json::to_string_pretty(&record).unwrap();
    let deserialized: DeploymentRecord = serde_json::from_str(&json).unwrap();

    assert_eq!(deserialized.dseq, record.dseq);
    assert_eq!(deserialized.owner, record.owner);
    assert_eq!(deserialized.label, record.label);
}
