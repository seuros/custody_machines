use super::*;

#[test]
fn a_missing_credential_is_empty_and_a_dangling_one_unreachable() {
    let dir = tempfile::tempdir().unwrap();
    let source = CredentialsDir::at(dir.path(), "vault");
    assert!(matches!(source.read(), Sighting::Empty));
    std::os::unix::fs::symlink("/nonexistent/credential", dir.path().join("vault")).unwrap();
    assert!(matches!(source.read(), Sighting::Unreachable(_)));
}
