//! Wildcard action matching for IAM actions.
//!
//! AWS actions are case-insensitive and support wildcard patterns:
//! - `*` matches any sequence of characters
//! - `?` matches exactly one character

/// Check if an IAM action matches a wildcard pattern.
///
/// Matching is case-insensitive (AWS actions are case-insensitive in policies).
///
/// # Examples
///
/// ```
/// # use activable_ingest_iam::action_matches;
/// assert!(action_matches("s3:GetObject", "s3:GetObject"));
/// assert!(action_matches("s3:Get*", "s3:GetObject"));
/// assert!(action_matches("s3:Get*", "s3:GetBucketPolicy"));
/// assert!(!action_matches("s3:Get*", "s3:PutObject"));
/// assert!(action_matches("*", "iam:CreateUser"));
/// assert!(action_matches("s3:*", "s3:GetObject"));
/// ```
pub fn action_matches(pattern: &str, action: &str) -> bool {
    let pattern_lower = pattern.to_lowercase();
    let action_lower = action.to_lowercase();

    // Fast path: if no wildcards, just compare strings
    if !pattern_lower.contains('*') && !pattern_lower.contains('?') {
        return pattern_lower == action_lower;
    }

    // Use simple wildcard matching
    wildcard_match(&pattern_lower, &action_lower)
}

/// Simple wildcard matching where `*` matches any sequence and `?` matches exactly one char.
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

    // Pattern exhausted but text remains: no match (unless we had trailing * handling)
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
    fn action_exact_match() {
        assert!(action_matches("s3:GetObject", "s3:GetObject"));
    }

    #[test]
    fn action_wildcard_suffix() {
        assert!(action_matches("s3:Get*", "s3:GetObject"));
        assert!(action_matches("s3:Get*", "s3:GetBucketPolicy"));
        assert!(!action_matches("s3:Get*", "s3:PutObject"));
    }

    #[test]
    fn action_star_matches_all() {
        assert!(action_matches("*", "iam:CreateUser"));
        assert!(action_matches("s3:*", "s3:GetObject"));
    }

    #[test]
    fn action_case_insensitive() {
        assert!(action_matches("s3:getobject", "s3:GetObject"));
        assert!(action_matches("S3:GETOBJECT", "s3:getobject"));
    }

    #[test]
    fn action_question_mark_wildcard() {
        assert!(action_matches("s3:Get?bject", "s3:GetObject"));
        assert!(!action_matches("s3:Get?bject", "s3:GetBucketPolicy"));
    }

    #[test]
    fn action_wildcard_in_middle() {
        assert!(action_matches("s3:*Object", "s3:GetObject"));
        assert!(action_matches("s3:*Object", "s3:PutObject"));
        assert!(!action_matches("s3:*Object", "s3:ListBuckets"));
    }

    #[test]
    fn action_multiple_wildcards() {
        assert!(action_matches("*:Get*", "s3:GetObject"));
        assert!(action_matches("*:Get*", "iam:GetUser"));
    }
}
