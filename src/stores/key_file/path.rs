//! Walking a key's path the way the kernel does: one component at a time,
//! following every symlink. Syncing and trust checks both run on that walk,
//! so nothing used to reach the key escapes either.

use std::collections::VecDeque;
use std::fs::{self, DirBuilder, File};
use std::io::ErrorKind;
use std::os::unix::fs::{DirBuilderExt, MetadataExt};
use std::path::{Component, Path, PathBuf};

use rustix::process::geteuid;

/// The most symlinks followed while resolving a key's path, as `MAXSYMLINKS`.
const MAX_SYMLINK_HOPS: usize = 40;

/// Everything used to reach a path.
struct Walk {
    /// Every directory that holds an entry on the way, in order.
    holders: Vec<PathBuf>,
    /// Every symlink followed.
    links: Vec<PathBuf>,
    /// What the path resolves to.
    target: PathBuf,
}

fn walk(path: &Path) -> std::io::Result<Walk> {
    let start = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()?.join(path)
    };
    let mut pending = components(&start);
    let mut current = PathBuf::from("/");
    let mut holders: Vec<PathBuf> = Vec::new();
    let mut links = Vec::new();
    while let Some(part) = pending.pop_front() {
        match part.components().next() {
            Some(Component::RootDir) => current = PathBuf::from("/"),
            Some(Component::ParentDir) => {
                current.pop();
            }
            Some(Component::Normal(_)) => {
                let next = current.join(&part);
                if !holders.contains(&current) {
                    holders.push(current.clone());
                }
                if fs::symlink_metadata(&next)?.file_type().is_symlink() {
                    if links.len() >= MAX_SYMLINK_HOPS {
                        return Err(std::io::Error::other("too many levels of symbolic links"));
                    }
                    for piece in components(&fs::read_link(&next)?).into_iter().rev() {
                        pending.push_front(piece);
                    }
                    links.push(next);
                } else {
                    current = next;
                }
            }
            Some(Component::CurDir | Component::Prefix(_)) | None => {}
        }
    }
    Ok(Walk {
        holders,
        links,
        target: current,
    })
}

/// Sync every directory that holds an entry used to reach `path`, and what
/// it resolves to. Run on every read and write: a crash or a failed sync
/// earlier is healed before the key counts as durable. Only a read-only
/// filesystem is excused.
pub(super) fn sync_chain(path: &Path) -> std::io::Result<()> {
    let walk = walk(path)?;
    for holder in walk.holders.iter().chain([&walk.target]) {
        tolerate_read_only(sync_dir(holder))?;
    }
    Ok(())
}

/// As OpenSSH's `StrictModes`, over everything used to reach `path`: every
/// symlink followed and every directory holding an entry on the way belong
/// to this user or root, and nobody else may write those directories. Above
/// the key's own directory, a sticky world-writable one such as `/tmp` is
/// allowed. So nobody else can repoint a link or rename a directory between
/// calls and swap in another key.
pub(super) fn trust(path: &Path) -> Result<(), String> {
    let shown = path.display();
    let walk = walk(path).map_err(|error| format!("cannot resolve {shown}: {error}"))?;
    let euid = geteuid().as_raw();
    let owned = |entry: &Path, uid: u32| {
        if uid == euid || uid == 0 {
            Ok(())
        } else {
            Err(format!(
                "{} is owned by uid {uid}, not by uid {euid} or root",
                entry.display()
            ))
        }
    };
    for link in &walk.links {
        let metadata = fs::symlink_metadata(link)
            .map_err(|error| format!("cannot inspect {}: {error}", link.display()))?;
        owned(link, metadata.uid())?;
    }
    let target_is_dir = fs::metadata(&walk.target).is_ok_and(|m| m.is_dir());
    let key_dir = if target_is_dir {
        Some(&walk.target)
    } else {
        walk.holders.last()
    };
    let dirs = walk
        .holders
        .iter()
        .chain(target_is_dir.then_some(&walk.target));
    for dir in dirs {
        let metadata = fs::metadata(dir)
            .map_err(|error| format!("cannot inspect {}: {error}", dir.display()))?;
        owned(dir, metadata.uid())?;
        let shared = metadata.mode() & 0o022 != 0;
        let sticky = metadata.mode() & 0o1000 != 0;
        if shared && (Some(dir) == key_dir || !sticky) {
            return Err(format!(
                "{} is writable by group or others; chmod go-w it",
                dir.display()
            ));
        }
    }
    Ok(())
}

/// Create the missing directories down to `dir`, each `0700`.
pub(super) fn create_dirs(dir: &Path) -> std::io::Result<()> {
    let mut missing = Vec::new();
    let mut cursor = Some(dir);
    while let Some(path) = cursor.filter(|path| !path.as_os_str().is_empty() && !path.exists()) {
        missing.push(path);
        cursor = path.parent();
    }
    for path in missing.into_iter().rev() {
        match DirBuilder::new().mode(0o700).create(path) {
            Err(error) if error.kind() != ErrorKind::AlreadyExists => return Err(error),
            Ok(()) | Err(_) => {}
        }
    }
    Ok(())
}

pub(super) fn sync_dir(dir: &Path) -> std::io::Result<()> {
    File::open(dir)?.sync_all()
}

pub(super) fn tolerate_read_only(result: std::io::Result<()>) -> std::io::Result<()> {
    match result {
        Err(error) if error.kind() == ErrorKind::ReadOnlyFilesystem => Ok(()),
        other => other,
    }
}

fn components(path: &Path) -> VecDeque<PathBuf> {
    path.components()
        .map(|part| PathBuf::from(part.as_os_str()))
        .collect()
}
