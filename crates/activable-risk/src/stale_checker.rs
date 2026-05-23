/// Check if a risk score is stale (older than the latest ingestion).
///
/// Uses lexicographic comparison of ISO 8601 timestamps, which works correctly
/// because ISO 8601 format sorts chronologically by string comparison.
pub fn is_stale(score_timestamp: &str, ingest_timestamp: &str) -> bool {
    score_timestamp < ingest_timestamp
}

/// Check if a risk score is stale, with None always considered stale.
///
/// Returns true if:
/// - score_timestamp is None (no previous score)
/// - score_timestamp < ingest_timestamp (score is older than ingestion)
pub fn is_stale_option(score_timestamp: Option<&str>, ingest_timestamp: &str) -> bool {
    match score_timestamp {
        None => true,
        Some(t) => is_stale(t, ingest_timestamp),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn score_is_stale_when_older_than_ingest() {
        let score_time = "2026-05-23T10:00:00Z";
        let ingest_time = "2026-05-23T11:00:00Z";
        assert!(is_stale(score_time, ingest_time));
    }

    #[test]
    fn score_is_fresh_when_newer_than_ingest() {
        let score_time = "2026-05-23T12:00:00Z";
        let ingest_time = "2026-05-23T11:00:00Z";
        assert!(!is_stale(score_time, ingest_time));
    }

    #[test]
    fn score_is_fresh_when_equal_to_ingest() {
        let score_time = "2026-05-23T11:00:00Z";
        let ingest_time = "2026-05-23T11:00:00Z";
        assert!(!is_stale(score_time, ingest_time));
    }

    #[test]
    fn no_score_is_always_stale() {
        let ingest_time = "2026-05-23T11:00:00Z";
        assert!(is_stale_option(None, ingest_time));
    }

    #[test]
    fn some_score_checks_timestamp() {
        let ingest_time = "2026-05-23T11:00:00Z";
        assert!(is_stale_option(Some("2026-05-23T10:00:00Z"), ingest_time));
        assert!(!is_stale_option(Some("2026-05-23T12:00:00Z"), ingest_time));
    }
}
