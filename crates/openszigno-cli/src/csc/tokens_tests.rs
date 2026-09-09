//! What a login leaves on disk, and how a later run reads it.

use super::*;

fn tokens(refresh: Option<&str>, expires_in: Option<u64>) -> Tokens {
    Tokens {
        access_token: Zeroizing::new("synthetic-access-token".to_owned()),
        refresh_token: refresh.map(|value| Zeroizing::new(value.to_owned())),
        expires_in,
    }
}

#[test]
fn the_record_sits_beside_the_token_file() {
    assert_eq!(
        record_path(Path::new("/tmp/csc/token")),
        PathBuf::from("/tmp/csc/token.record.json")
    );
}

#[test]
fn an_expiry_is_reached_a_minute_early_and_an_absent_one_never() {
    let record = Record {
        expires_at: Some(1_000),
        ..Record::default()
    };
    assert!(!record.is_expired(900));
    assert!(record.is_expired(950));
    assert!(record.is_expired(2_000));
    assert!(!Record::default().is_expired(u64::MAX));
}

#[test]
fn storing_writes_the_token_and_its_record_and_reads_them_back() {
    let directory = tempfile::tempdir().expect("a temporary directory");
    let path = directory.path().join("token");
    let record = store(
        &path,
        &tokens(Some("synthetic-refresh-token"), Some(600)),
        "https://as.example/oauth2/token",
        1_000,
    )
    .expect("the token is stored");
    assert_eq!(record.expires_at, Some(1_600));
    assert_eq!(
        std::fs::read_to_string(&path).expect("the token file is written"),
        "synthetic-access-token"
    );
    let read = load_record(&path)
        .expect("the record loads")
        .expect("there is one");
    assert_eq!(read.expires_at, Some(1_600));
    assert_eq!(
        read.refresh_token.as_deref(),
        Some("synthetic-refresh-token")
    );
    assert_eq!(
        read.token_url.as_deref(),
        Some("https://as.example/oauth2/token")
    );
}

/// Both files hold a secret, so both are created readable by their owner and
/// nobody else, and a second login replaces rather than appends.
#[cfg(unix)]
#[test]
fn both_files_are_created_private_and_are_replaced_in_place() {
    use std::os::unix::fs::PermissionsExt as _;

    let directory = tempfile::tempdir().expect("a temporary directory");
    let path = directory.path().join("token");
    store(&path, &tokens(Some("r1"), Some(60)), "https://as/token", 0)
        .expect("the token is stored");
    for file in [path.clone(), record_path(&path)] {
        let mode = std::fs::metadata(&file)
            .expect("the file exists")
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600, "{}", file.display());
    }
    store(&path, &tokens(None, None), "https://as/token", 0).expect("the token is replaced");
    let read = load_record(&path)
        .expect("the record loads")
        .expect("there is one");
    assert_eq!(read.refresh_token, None);
    assert_eq!(read.expires_at, None);
    assert_eq!(
        std::fs::read_to_string(&path).expect("the token file is read"),
        "synthetic-access-token"
    );
}

#[test]
fn a_missing_record_is_absence_and_a_corrupt_one_is_a_refusal() {
    let directory = tempfile::tempdir().expect("a temporary directory");
    let path = directory.path().join("token");
    assert!(
        load_record(&path)
            .expect("no record is not an error")
            .is_none()
    );
    std::fs::write(record_path(&path), b"{not json").expect("the record is written");
    let error = load_record(&path).expect_err("a corrupt record is refused");
    assert_eq!(error.code(), SignErrorCode::CscTokenUnusable);
}

#[test]
fn a_token_file_that_cannot_be_created_is_a_refusal_and_not_a_panic() {
    let directory = tempfile::tempdir().expect("a temporary directory");
    let path = directory.path().join("no-such-directory").join("token");
    let error = store(&path, &tokens(None, None), "https://as/token", 0)
        .expect_err("the parent does not exist");
    assert_eq!(error.code(), SignErrorCode::CscTokenUnusable);
}
