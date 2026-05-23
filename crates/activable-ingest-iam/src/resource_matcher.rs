//! Wildcard resource (ARN) pattern matching for IAM policies.
//!
//! ARN patterns support wildcards:
//! - `*` alone matches any resource
//! - `arn:aws:s3:::my-bucket/*` matches any object in the bucket
//! - Wildcards can appear in any ARN segment

/// Check if an IAM resource (ARN) matches a wildcard pattern.
///
/// ARN patterns are matched segment-by-segment, supporting `*` and `?` wildcards.
///
/// # Examples
///
/// ```
/// # use activable_ingest_iam::resource_matches;
/// assert!(resource_matches("arn:aws:s3:::my-bucket", "arn:aws:s3:::my-bucket"));
/// assert!(resource_matches("arn:aws:s3:::my-bucket/*", "arn:aws:s3:::my-bucket/path/to/object.txt"));
/// assert!(resource_matches("*", "arn:aws:iam::123456789012:user/alice"));
/// assert!(resource_matches("arn:aws:iam::123456789012:user/dev-*", "arn:aws:iam::123456789012:user/dev-alice"));
/// ```
pub fn resource_matches(pattern: &str, resource: &str) -> bool {
    // Special case: `*` alone matches anything
    if pattern == "*" {
        return true;
    }

    // Fast path: if no wildcards, just compare strings
    if !pattern.contains('*') && !pattern.contains('?') {
        return pattern == resource;
    }

    // Use wildcard matching
    wildcard_match(pattern, resource)
}

/// Wildcard matching for ARN patterns where `*` matches any sequence and `?` matches exactly one char.
fn wildcard_match(pattern: &str, text: &str) -> bool {
    let pattern_chars: Vec<char> = pattern.chars().collect();
    let text_chars: Vec<char> = text.chars().collect();

    match_recursive(&pattern_chars, &text_chars, 0, 0)
}

/// Recursive wildcard matching implementation.
fn match_recursive(pattern: &[char], text: &[char], p_idx: usize, t_idx: usize) -> bool {
    // Both exhausted: match
    if p_idx == pattern.len() && t_idx == text.len() {
        return true;
    }

    // Pattern exhausted but text remains: no match (unless trailing * was handled)
    if p_idx == pattern.len() {
        return false;
    }

    // Pattern char is `*`
    if pattern[p_idx] == '*' {
        // `*` at end of pattern matches everything remaining
        if p_idx == pattern.len() - 1 {
            return true;
        }

        // Try matching the rest of the pattern at each position in the text
        for next_t_idx in t_idx..=text.len() {
            if match_recursive(pattern, text, p_idx + 1, next_t_idx) {
                return true;
            }
        }

        return false;
    }

    // Text exhausted but pattern remains: no match
    if t_idx == text.len() {
        return false;
    }

    // Pattern char is `?`: matches exactly one character
    if pattern[p_idx] == '?' {
        return match_recursive(pattern, text, p_idx + 1, t_idx + 1);
    }

    // Regular character: must match exactly
    if pattern[p_idx] == text[t_idx] {
        return match_recursive(pattern, text, p_idx + 1, t_idx + 1);
    }

    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn arn_exact_match() {
        assert!(resource_matches(
            "arn:aws:s3:::my-bucket",
            "arn:aws:s3:::my-bucket"
        ));
    }

    #[test]
    fn arn_wildcard_suffix() {
        assert!(resource_matches(
            "arn:aws:s3:::my-bucket/*",
            "arn:aws:s3:::my-bucket/path/to/object.txt"
        ));
    }

    #[test]
    fn arn_star_matches_all() {
        assert!(resource_matches(
            "*",
            "arn:aws:iam::123456789012:user/alice"
        ));
        assert!(resource_matches("*", "arn:aws:s3:::bucket"));
    }

    #[test]
    fn arn_partial_wildcard_in_segment() {
        assert!(resource_matches(
            "arn:aws:iam::123456789012:user/dev-*",
            "arn:aws:iam::123456789012:user/dev-alice"
        ));
        assert!(resource_matches(
            "arn:aws:iam::123456789012:user/dev-*",
            "arn:aws:iam::123456789012:user/dev-bob-test"
        ));
    }

    #[test]
    fn arn_no_match_partial_prefix() {
        assert!(!resource_matches(
            "arn:aws:iam::123456789012:user/dev-*",
            "arn:aws:iam::123456789012:user/admin-alice"
        ));
    }

    #[test]
    fn arn_multiple_wildcards() {
        assert!(resource_matches(
            "arn:aws:s3:::*-prod-*",
            "arn:aws:s3:::data-prod-2025"
        ));
    }

    #[test]
    fn arn_question_mark_wildcard() {
        assert!(resource_matches(
            "arn:aws:s3:::bucket-200?",
            "arn:aws:s3:::bucket-2005"
        ));
        assert!(!resource_matches(
            "arn:aws:s3:::bucket-200?",
            "arn:aws:s3:::bucket-20025"
        ));
    }
}
