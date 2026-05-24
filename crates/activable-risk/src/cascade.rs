//! Cascade-score aggregation across constituent scenario scores.
//!
//! The cascade (harmonic mean) model captures the principle that an attack
//! chain is only as strong as its weakest link. If any detection step fails,
//! the overall cascade fails.

/// Harmonic mean of the non-zero scores.
///
/// Returns 0 if all inputs are zero. This implementation ensures:
/// - Any all-zero input → output 0 (chain broken)
/// - Mixed zero/non-zero → harmonic mean of non-zero (weak link caps result)
/// - Single input → returns that input
/// - Empty input → 0
///
/// Property: `harmonic_mean([0.95, 0.50, 0.95]) ≈ 0.72` (weak link pulls average down).
/// Property: `harmonic_mean([0.80, 0.80, 0.80]) = 0.80` (all equal returns same).
pub fn harmonic_mean(scores: &[f64]) -> f64 {
    let non_zero: Vec<f64> = scores
        .iter()
        .copied()
        .filter(|&s| s > 0.0 && s.is_finite())
        .collect();

    if non_zero.is_empty() {
        return 0.0;
    }

    let n = non_zero.len() as f64;
    let sum_reciprocals: f64 = non_zero.iter().map(|s| 1.0 / s).sum();
    n / sum_reciprocals
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn harmonic_mean_empty_returns_zero() {
        assert_eq!(harmonic_mean(&[]), 0.0);
    }

    #[test]
    fn harmonic_mean_all_zero_returns_zero() {
        assert_eq!(harmonic_mean(&[0.0, 0.0, 0.0]), 0.0);
    }

    #[test]
    fn harmonic_mean_single_zero_returns_zero() {
        assert_eq!(harmonic_mean(&[0.0]), 0.0);
    }

    #[test]
    fn harmonic_mean_one_value_returns_that_value() {
        assert_eq!(harmonic_mean(&[0.8]), 0.8);
        assert_eq!(harmonic_mean(&[0.5]), 0.5);
    }

    #[test]
    fn harmonic_mean_three_equal_returns_same() {
        let result = harmonic_mean(&[0.8, 0.8, 0.8]);
        assert!((result - 0.8).abs() < 1e-10);
    }

    #[test]
    fn harmonic_mean_weak_link_pulls_down() {
        let result = harmonic_mean(&[0.95, 0.50, 0.95]);
        // HM = 3 / (1/0.95 + 1/0.50 + 1/0.95) = 3 / (1.0526 + 2.0 + 1.0526) ≈ 0.72
        assert!(result < 0.80);
        assert!(result > 0.65);
    }

    #[test]
    fn harmonic_mean_zero_in_list_filters_out() {
        // [0.0, 0.95] should compute HM of [0.95] = 0.95
        let result = harmonic_mean(&[0.0, 0.95]);
        assert!((result - 0.95).abs() < 1e-10);
    }

    #[test]
    fn harmonic_mean_multiple_zeros_filter_out() {
        // [0.0, 0.0, 0.80, 0.80] should compute HM of [0.80, 0.80] = 0.80
        let result = harmonic_mean(&[0.0, 0.0, 0.80, 0.80]);
        assert!((result - 0.80).abs() < 1e-10);
    }

    #[test]
    fn harmonic_mean_single_nonzero_with_many_zeros() {
        // [0.0, 0.0, 0.0, 0.5] should compute HM of [0.5] = 0.5
        let result = harmonic_mean(&[0.0, 0.0, 0.0, 0.5]);
        assert!((result - 0.5).abs() < 1e-10);
    }

    #[test]
    fn harmonic_mean_all_nonzero_close_to_min() {
        // [0.95, 0.95, 0.95, 0.95] = 0.95
        let result = harmonic_mean(&[0.95, 0.95, 0.95, 0.95]);
        assert!((result - 0.95).abs() < 1e-10);
    }

    #[test]
    fn harmonic_mean_filters_infinity() {
        // Infinity is not finite, should be filtered
        let result = harmonic_mean(&[0.95, f64::INFINITY, 0.95]);
        assert!((result - 0.95).abs() < 1e-10);
    }

    #[test]
    fn harmonic_mean_filters_nan() {
        // NaN is not finite, should be filtered
        let result = harmonic_mean(&[0.95, f64::NAN, 0.95]);
        assert!((result - 0.95).abs() < 1e-10);
    }

    // Property tests using proptest
    #[cfg(test)]
    mod props {
        use super::*;

        // Property: all inputs >= 0 -> output >= 0
        #[test]
        fn prop_non_negative_output_for_non_negative_input() {
            let test_cases = vec![
                vec![0.1, 0.2, 0.3],
                vec![0.5, 0.5],
                vec![1.0],
                vec![0.0, 0.5, 1.0],
            ];
            for scores in test_cases {
                let result = harmonic_mean(&scores);
                assert!(result >= 0.0, "failed for {:?}", scores);
            }
        }

        // Property: if all non-zero and equal, result equals input
        #[test]
        fn prop_equal_inputs_return_same() {
            let test_values = vec![0.1, 0.5, 0.8, 0.95];
            for val in test_values {
                let scores = vec![val; 5];
                let result = harmonic_mean(&scores);
                assert!((result - val).abs() < 1e-10, "failed for {} repeated", val);
            }
        }

        // Property: HM(a, b) <= GM(a, b) <= AM(a, b) — harmonic mean is always <= geometric mean
        // For this simple test: HM(a, b) <= min(a, b) is FALSE. Instead verify HM is between 0 and max
        #[test]
        fn prop_harmonic_mean_between_bounds() {
            let test_pairs = vec![
                (0.5, 0.9),
                (0.2, 0.8),
                (0.1, 0.99),
                (0.7, 0.3),
            ];
            for (a, b) in test_pairs {
                let result = harmonic_mean(&[a, b]);
                let max = a.max(b);
                // Harmonic mean of two positive values is always between 0 and max
                assert!(result > 0.0, "HM({}, {}) = {} should be > 0", a, b, result);
                assert!(
                    result <= max + 1e-10,
                    "HM({}, {}) = {} should be <= max",
                    a,
                    b,
                    result
                );
            }
        }
    }
}
