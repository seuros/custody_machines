use std::os::unix::fs::PermissionsExt;

use super::*;

fn mode(path: &Path) -> u32 {
    fs::metadata(path).unwrap().permissions().mode() & 0o777
}

#[test]
fn a_missing_file_is_empty_not_unreachable() {
    let dir = tempfile::tempdir().unwrap();
    let file = KeyFile::new(dir.path().join("nested/vault.key"));
    assert!(matches!(file.read(), Sighting::Empty));
}

#[test]
fn writes_create_owner_only_dir_and_file_and_read_back() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("secrets/vault.key");
    let file = KeyFile::new(&path);
    file.write(b"key one").unwrap();
    assert_eq!(mode(&path), 0o600);
    assert_eq!(mode(path.parent().unwrap()), 0o700);
    let Sighting::Holds(key) = KeyFile::new(&path).read() else {
        panic!("no key")
    };
    assert_eq!(key.as_slice(), b"key one");
    let leftovers = fs::read_dir(path.parent().unwrap()).unwrap().count();
    assert_eq!(leftovers, 1, "no temp files left behind");
}

#[test]
fn a_write_never_replaces_an_existing_key() {
    let dir = tempfile::tempdir().unwrap();
    let file = KeyFile::new(dir.path().join("vault.key"));
    file.write(b"first").unwrap();
    let error = file.write(b"second").unwrap_err();
    assert!(error.to_string().contains("cannot write"), "{error}");
    let Sighting::Holds(key) = file.read() else {
        panic!("no key")
    };
    assert_eq!(key.as_slice(), b"first");
}

#[test]
fn a_group_readable_file_is_refused_with_the_reason() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("vault.key");
    fs::write(&path, b"key").unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o640)).unwrap();
    let Sighting::Unreachable(error) = KeyFile::new(&path).read() else {
        panic!("used it")
    };
    assert!(error.to_string().contains("chmod 600"), "{error}");
}

#[test]
fn an_empty_file_is_unreachable_not_a_key() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("vault.key");
    fs::write(&path, b"").unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
    assert!(matches!(
        KeyFile::new(&path).read(),
        Sighting::Unreachable(_)
    ));
}

#[test]
fn a_key_behind_chained_symlinks_reads_and_writes() {
    let dir = tempfile::tempdir().unwrap();
    let real = dir.path().join("z");
    fs::create_dir(&real).unwrap();
    fs::create_dir(dir.path().join("x")).unwrap();
    std::os::unix::fs::symlink(&real, dir.path().join("x/link2")).unwrap();
    std::os::unix::fs::symlink("x/link2", dir.path().join("a")).unwrap();
    let file = KeyFile::new(dir.path().join("a/vault.key"));
    file.write(b"linked").unwrap();
    let Sighting::Holds(key) = file.read() else {
        panic!("no key")
    };
    assert_eq!(key.as_slice(), b"linked");
    assert!(real.join("vault.key").exists());
}

#[test]
fn a_symlink_loop_is_unreachable_not_a_hang() {
    let dir = tempfile::tempdir().unwrap();
    std::os::unix::fs::symlink("loop", dir.path().join("loop")).unwrap();
    let file = KeyFile::new(dir.path().join("loop/vault.key"));
    assert!(matches!(
        file.read(),
        Sighting::Unreachable(_) | Sighting::Empty
    ));
    assert!(file.write(b"k").is_err());
}

#[test]
fn a_crashed_write_leaves_no_stray_copy_after_the_next_read() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("vault.key");
    let file = KeyFile::new(&path);
    file.write(b"published").unwrap();
    let stray = dir.path().join(".vault.key.custody-tmp.4242.0");
    let unrelated = dir.path().join(".vault.key.custody-tmp.backup");
    fs::write(&unrelated, b"someone else").unwrap();
    fs::write(&stray, b"published").unwrap();
    assert!(matches!(file.read(), Sighting::Holds(_)));
    assert!(!stray.exists());
    assert!(unrelated.exists(), "only our own namespace is swept");
    fs::remove_file(&path).unwrap();
    fs::write(&stray, b"published").unwrap();
    assert!(matches!(file.read(), Sighting::Empty));
    assert!(!stray.exists(), "swept even when no key is published");
}

#[test]
fn a_final_symlink_is_followed_on_read_and_never_written_through() {
    let dir = tempfile::tempdir().unwrap();
    let target = dir.path().join("other/key");
    KeyFile::new(&target).write(b"target").unwrap();
    let link = dir.path().join("current");
    std::os::unix::fs::symlink("other/key", &link).unwrap();
    let Sighting::Holds(key) = KeyFile::new(&link).read() else {
        panic!("no key")
    };
    assert_eq!(key.as_slice(), b"target");
    assert!(KeyFile::new(&link).write(b"other").is_err());
}

#[test]
fn short_and_exact_length_keys_read_back_whole() {
    let dir = tempfile::tempdir().unwrap();
    for key in [&b"k"[..], &[7; 31], &[9; 4096]] {
        let path = dir.path().join(format!("key-{}", key.len()));
        KeyFile::new(&path).write(key).unwrap();
        let Sighting::Holds(read) = KeyFile::new(&path).read() else {
            panic!("no key")
        };
        assert_eq!(read.as_slice(), key);
    }
}

#[test]
fn a_dangling_symlink_is_unreachable_not_empty() {
    let dir = tempfile::tempdir().unwrap();
    std::os::unix::fs::symlink("/nonexistent/custody/key", dir.path().join("vault.key")).unwrap();
    assert!(matches!(
        KeyFile::new(dir.path().join("vault.key")).read(),
        Sighting::Unreachable(_)
    ));
}

#[test]
fn a_key_in_a_directory_others_may_write_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("vault.key");
    KeyFile::new(&path).write(b"k").unwrap();
    fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o777)).unwrap();
    let Sighting::Unreachable(error) = KeyFile::new(&path).read() else {
        panic!("used it")
    };
    assert!(error.to_string().contains("go-w"), "{error}");
    fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o700)).unwrap();
}

#[test]
fn reserved_temp_names_are_refused_as_key_files() {
    let dir = tempfile::tempdir().unwrap();
    let file = KeyFile::new(dir.path().join(".vault.key.custody-tmp.1.2"));
    assert!(matches!(file.read(), Sighting::Unreachable(_)));
    assert!(file.write(b"k").is_err());
}

#[test]
fn a_dangling_parent_component_is_unreachable_not_empty() {
    let dir = tempfile::tempdir().unwrap();
    std::os::unix::fs::symlink("/nonexistent/custody", dir.path().join("current")).unwrap();
    let file = KeyFile::new(dir.path().join("current/vault.key"));
    assert!(matches!(file.read(), Sighting::Unreachable(_)));
    let fresh = KeyFile::new(dir.path().join("not/yet/created/vault.key"));
    assert!(
        matches!(fresh.read(), Sighting::Empty),
        "a fresh install is still empty"
    );
}

#[test]
fn a_writable_ancestor_without_the_sticky_bit_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("inner/vault.key");
    KeyFile::new(&path).write(b"k").unwrap();
    fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o777)).unwrap();
    assert!(matches!(
        KeyFile::new(&path).read(),
        Sighting::Unreachable(_)
    ));
    fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o1777)).unwrap();
    assert!(
        matches!(KeyFile::new(&path).read(), Sighting::Holds(_)),
        "sticky is fine"
    );
    fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o700)).unwrap();
}

#[test]
fn a_symlink_through_a_directory_others_may_write_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let private = dir.path().join("private");
    KeyFile::new(private.join("vault.key")).write(b"k").unwrap();
    let shared = dir.path().join("shared");
    fs::create_dir(&shared).unwrap();
    std::os::unix::fs::symlink(&private, shared.join("link")).unwrap();
    fs::set_permissions(&shared, fs::Permissions::from_mode(0o777)).unwrap();
    let through = KeyFile::new(shared.join("link/vault.key"));
    let Sighting::Unreachable(error) = through.read() else {
        panic!("trusted it")
    };
    assert!(error.to_string().contains("go-w"), "{error}");
    assert!(matches!(
        KeyFile::new(private.join("vault.key")).read(),
        Sighting::Holds(_)
    ));
}
