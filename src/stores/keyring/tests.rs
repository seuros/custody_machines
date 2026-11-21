use super::*;

fn account() -> String {
    format!("custody-test-{}", std::process::id())
}

#[test]
fn keyutils_is_a_volatile_cache_that_round_trips() {
    let source = KeyringSource::keyutils("custody-machines", account());
    assert_eq!(source.spec(), SourceSpec::cache());
    if let Sighting::Unreachable(error) = source.read() {
        eprintln!("no usable session keyring here: {error}");
        return;
    }
    source.write(b"cached").unwrap();
    let Sighting::Holds(key) = source.read() else {
        panic!("no key after write")
    };
    assert_eq!(key.as_slice(), b"cached");
    source.entry().unwrap().delete_credential().unwrap();
    assert!(matches!(source.read(), Sighting::Empty));
}

#[test]
fn a_missing_secret_service_is_unreachable_never_empty() {
    let source = KeyringSource::secret_service("custody-machines", account());
    assert_eq!(source.spec(), SourceSpec::durable());
    match source.read() {
        Sighting::Unreachable(error) => {
            assert!(error.to_string().contains("Secret Service"), "{error}");
        }
        Sighting::Empty | Sighting::Holds(_) => {}
    }
}
