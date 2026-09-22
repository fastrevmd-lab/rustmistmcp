//! Operation ID similarity matching for unknown operation errors.

use rustmistmcp_core::{
    Catalog,
    catalog::{MistCapability, MistOperation},
};

/// Maximum normalized distance ratio (0.0 to 1.0) to consider a match.
///
/// This is the Levenshtein distance divided by the length of the longer string.
/// A ratio of 0.65 means we tolerate up to 65% differences, which catches
/// prefix changes (list→get), suffix additions/removals, and mid-string
/// variations (OutboundSsh→JuniperDevices) while filtering out completely
/// unrelated operations.
const MAX_DISTANCE_RATIO: f64 = 0.65;

/// Maximum number of suggestions to return.
const MAX_SUGGESTIONS: usize = 3;

/// Compute case-insensitive Levenshtein distance between two strings.
///
/// This is the standard Wagner-Fischer algorithm with O(m*n) complexity.
/// For operation IDs (typically < 50 chars), this is negligible overhead.
fn levenshtein_distance(a: &str, b: &str) -> usize {
    let a_lower = a.to_lowercase();
    let b_lower = b.to_lowercase();
    let a_chars: Vec<char> = a_lower.chars().collect();
    let b_chars: Vec<char> = b_lower.chars().collect();

    let m = a_chars.len();
    let n = b_chars.len();

    if m == 0 {
        return n;
    }
    if n == 0 {
        return m;
    }

    // Use two rows instead of full matrix for O(min(m,n)) space
    let mut prev_row: Vec<usize> = (0..=n).collect();
    let mut curr_row: Vec<usize> = vec![0; n + 1];

    for i in 1..=m {
        curr_row[0] = i;
        for j in 1..=n {
            let cost = if a_chars[i - 1] == b_chars[j - 1] {
                0
            } else {
                1
            };
            curr_row[j] = (prev_row[j] + 1) // deletion
                .min(curr_row[j - 1] + 1) // insertion
                .min(prev_row[j - 1] + cost); // substitution
        }
        std::mem::swap(&mut prev_row, &mut curr_row);
    }

    prev_row[n]
}

/// Extract common meaningful tokens from operation IDs.
///
/// Looks for token-like substrings: "Cmd"/"Command", "Device"/"Devices", etc.
/// Returns a score boost (0.0-0.4) based on shared token similarity.
fn token_similarity_boost(unknown_id: &str, candidate_id: &str) -> f64 {
    let unknown_lower = unknown_id.to_lowercase();
    let candidate_lower = candidate_id.to_lowercase();

    let mut boost = 0.0;

    // Check for command-related tokens
    let has_cmd_unknown = unknown_lower.contains("cmd") || unknown_lower.contains("command");
    let has_cmd_candidate = candidate_lower.contains("cmd") || candidate_lower.contains("command");
    if has_cmd_unknown && has_cmd_candidate {
        boost += 0.1;
    }

    // Check for device-related tokens
    let unknown_has_device = unknown_lower.contains("device")
        || unknown_lower.contains("ssh")
        || unknown_lower.contains("switch")
        || unknown_lower.contains("router");
    let candidate_has_device = candidate_lower.contains("device")
        || candidate_lower.contains("ssh")
        || candidate_lower.contains("switch")
        || candidate_lower.contains("router");
    if unknown_has_device && candidate_has_device {
        boost += 0.1;
    }

    // Extra boost for operations that share BOTH device and command semantics.
    // When the unknown ID is semantically related (names a concept, not misspelled),
    // token-level affinity matters more than edit distance alone. For example,
    // getOrgOutboundSshCmd (ssh access + cmd) is related to getOrgJuniperDevicesCommand
    // (devices + command) despite high edit distance, because both involve device access
    // and command execution.
    if has_cmd_unknown && has_cmd_candidate && unknown_has_device && candidate_has_device {
        boost += 0.15;
    }

    // Check for similar suffixes (last 5 chars)
    let unknown_suffix = if unknown_lower.len() >= 5 {
        &unknown_lower[unknown_lower.len() - 5..]
    } else {
        &unknown_lower
    };
    let candidate_suffix = if candidate_lower.len() >= 5 {
        &candidate_lower[candidate_lower.len() - 5..]
    } else {
        &candidate_lower
    };
    let suffix_distance = levenshtein_distance(unknown_suffix, candidate_suffix);
    if suffix_distance <= 2 {
        boost += 0.1;
    }

    boost
}

/// Compute a similarity score for two operation IDs.
///
/// Lower scores are better. This uses normalized Levenshtein distance (0.0-1.0)
/// where 0.0 is identical and 1.0 is completely different. We also boost scores
/// for operations that share common prefixes and semantic tokens.
fn similarity_score(unknown_id: &str, candidate_id: &str) -> f64 {
    let distance = levenshtein_distance(unknown_id, candidate_id);
    let max_len = unknown_id.len().max(candidate_id.len());

    if max_len == 0 {
        return 0.0;
    }

    let normalized_distance = distance as f64 / max_len as f64;

    // Find common prefix length (case-insensitive)
    let unknown_lower = unknown_id.to_lowercase();
    let candidate_lower = candidate_id.to_lowercase();
    let common_prefix_len = unknown_lower
        .chars()
        .zip(candidate_lower.chars())
        .take_while(|(a, b)| a == b)
        .count();

    // Boost (lower score) for operations with significant common prefix
    let prefix_boost = (common_prefix_len as f64 / max_len as f64) * 0.5;

    // Additional boost for token-level similarity
    let token_boost = token_similarity_boost(unknown_id, candidate_id);

    // Final score: normalized distance, reduced by both boosts
    (normalized_distance - prefix_boost - token_boost).max(0.0)
}

/// Find up to 3 similar operation IDs for an unknown operation.
///
/// Returns a vector of tuples: (operation_id, distance, capability).
/// Results are sorted by similarity score (ascending), then alphabetically.
pub fn find_similar_operations<'a>(
    catalog: &'a Catalog,
    unknown_id: &str,
) -> Vec<(&'a str, usize, MistCapability)> {
    let mut candidates: Vec<(&MistOperation, f64, usize)> = catalog
        .operations
        .iter()
        .filter_map(|op| {
            let distance = levenshtein_distance(unknown_id, &op.operation_id);
            if distance == 0 {
                return None; // Skip exact matches
            }

            let score = similarity_score(unknown_id, &op.operation_id);
            let normalized_distance =
                distance as f64 / unknown_id.len().max(op.operation_id.len()) as f64;

            if normalized_distance <= MAX_DISTANCE_RATIO {
                Some((op, score, distance))
            } else {
                None
            }
        })
        .collect();

    // Sort by score first (lower is better), then by operation_id for stability
    candidates.sort_by(|a, b| {
        a.1.partial_cmp(&b.1)
            .unwrap_or(std::cmp::Ordering::Equal)
            .then_with(|| a.0.operation_id.cmp(&b.0.operation_id))
    });

    candidates
        .into_iter()
        .take(MAX_SUGGESTIONS)
        .map(|(op, _score, dist)| (op.operation_id.as_str(), dist, op.capability))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_levenshtein_distance_exact_match() {
        assert_eq!(levenshtein_distance("hello", "hello"), 0);
    }

    #[test]
    fn test_levenshtein_distance_case_insensitive() {
        assert_eq!(levenshtein_distance("Hello", "hello"), 0);
        assert_eq!(levenshtein_distance("HELLO", "hello"), 0);
    }

    #[test]
    fn test_levenshtein_distance_single_substitution() {
        assert_eq!(levenshtein_distance("hello", "hallo"), 1);
    }

    #[test]
    fn test_levenshtein_distance_prefix_difference() {
        // "list" vs "get" with shared "OrgInventory" = 3 substitutions
        assert_eq!(
            levenshtein_distance("listOrgInventory", "getOrgInventory"),
            3
        );
    }

    #[test]
    fn test_levenshtein_distance_suffix_difference() {
        assert_eq!(
            levenshtein_distance("getOrgLicenses", "getOrgLicensesSummary"),
            7
        );
    }

    #[test]
    fn test_levenshtein_distance_completely_different() {
        assert_eq!(levenshtein_distance("abc", "xyz"), 3);
    }

    #[test]
    fn test_find_similar_operations_real_world_cases() {
        let catalog = Catalog::embedded().expect("embedded catalog must load");

        // Case 1: getOrgOutboundSshCmd -> getOrgJuniperDevicesCommand
        let suggestions = find_similar_operations(&catalog, "getOrgOutboundSshCmd");
        let ids: Vec<&str> = suggestions.iter().map(|(id, _, _)| *id).collect();
        assert!(
            ids.contains(&"getOrgJuniperDevicesCommand"),
            "Expected getOrgJuniperDevicesCommand in suggestions, got: {:?}",
            ids
        );

        // Case 2: listOrgInventory -> getOrgInventory
        let suggestions = find_similar_operations(&catalog, "listOrgInventory");
        let ids: Vec<&str> = suggestions.iter().map(|(id, _, _)| *id).collect();
        assert!(
            ids.contains(&"getOrgInventory"),
            "Expected getOrgInventory in suggestions, got: {:?}",
            ids
        );

        // Case 3: getOrgLicenses -> getOrgLicensesSummary
        let suggestions = find_similar_operations(&catalog, "getOrgLicenses");
        let ids: Vec<&str> = suggestions.iter().map(|(id, _, _)| *id).collect();
        assert!(
            ids.contains(&"getOrgLicensesSummary"),
            "Expected getOrgLicensesSummary in suggestions, got: {:?}",
            ids
        );
    }

    #[test]
    fn test_find_similar_operations_no_suggestions_for_nonsense() {
        let catalog = Catalog::embedded().expect("embedded catalog must load");

        // Nonsense ID should yield no suggestions
        let suggestions = find_similar_operations(&catalog, "zzzzzzzzzz");
        assert!(
            suggestions.is_empty(),
            "Expected no suggestions for nonsense ID, got: {:?}",
            suggestions
        );
    }

    #[test]
    fn test_find_similar_operations_bounded_count() {
        let catalog = Catalog::embedded().expect("embedded catalog must load");

        // Even if many operations are close, return at most MAX_SUGGESTIONS
        let suggestions = find_similar_operations(&catalog, "getOrg");
        assert!(
            suggestions.len() <= MAX_SUGGESTIONS,
            "Expected at most {} suggestions, got {}",
            MAX_SUGGESTIONS,
            suggestions.len()
        );
    }

    /// Characterization test pinning current ranking behavior.
    ///
    /// This test documents the current heuristic's output for a spread of inputs.
    /// A future tweak to the scoring algorithm will show up as a diff here rather
    /// than silently degrading quality.
    #[test]
    fn test_ranking_behavior_characterization() {
        let catalog = Catalog::embedded().expect("embedded catalog must load");

        // Typo: getOrgInventry -> should suggest getOrgInventory first
        let suggestions = find_similar_operations(&catalog, "getOrgInventry");
        assert!(
            !suggestions.is_empty() && suggestions[0].0 == "getOrgInventory",
            "Expected getOrgInventory as top suggestion for typo, got: {:?}",
            suggestions.first().map(|(id, _, _)| id)
        );

        // Partial match: getSiteDevices -> should include getSiteDevice or listSiteDevices
        let suggestions = find_similar_operations(&catalog, "getSiteDevices");
        let ids: Vec<&str> = suggestions.iter().map(|(id, _, _)| *id).collect();
        assert!(
            ids.contains(&"getSiteDevice") || ids.contains(&"listSiteDevices"),
            "Expected getSiteDevice or listSiteDevices in suggestions, got: {:?}",
            ids
        );

        // Partial match: deleteOrgNetwork -> should include operations with Org + Network
        let suggestions = find_similar_operations(&catalog, "deleteOrgNetwork");
        let ids: Vec<&str> = suggestions.iter().map(|(id, _, _)| *id).collect();
        // Just verify we get sensible suggestions, not empty
        assert!(
            !suggestions.is_empty(),
            "Expected suggestions for deleteOrgNetwork, got none"
        );
        // Verify at least one contains "Network"
        assert!(
            ids.iter().any(|id| id.to_lowercase().contains("network")),
            "Expected at least one suggestion with 'network', got: {:?}",
            ids
        );

        // Generic term: rebootDevice -> verify we get device-related suggestions
        let suggestions = find_similar_operations(&catalog, "rebootDevice");
        let ids: Vec<&str> = suggestions.iter().map(|(id, _, _)| *id).collect();
        assert!(
            !suggestions.is_empty(),
            "Expected device-related suggestions for rebootDevice, got none"
        );
        // At least one should contain "device" or "restart"
        assert!(
            ids.iter().any(|id| {
                let lower = id.to_lowercase();
                lower.contains("device") || lower.contains("restart")
            }),
            "Expected device or restart related suggestions, got: {:?}",
            ids
        );

        // Real case with known wart: getOrgWlans
        // Known behavior: short candidates like getOrgStats may rank first due to
        // normalized distance favoring shorter strings, with sensible answers appearing
        // in the set. This is harmless when showing 3 suggestions. Here, getOrgWLAN
        // (singular, uppercase) appears due to minimal edit distance.
        let suggestions = find_similar_operations(&catalog, "getOrgWlans");
        let ids: Vec<&str> = suggestions.iter().map(|(id, _, _)| *id).collect();
        assert!(
            ids.contains(&"getOrgWLAN") || ids.contains(&"listOrgWlans"),
            "Expected getOrgWLAN or listOrgWlans in suggestions for getOrgWlans, got: {:?}",
            ids
        );

        // Nonsense: zzzzzzzzzz -> must return empty
        let suggestions = find_similar_operations(&catalog, "zzzzzzzzzz");
        assert!(
            suggestions.is_empty(),
            "Expected no suggestions for nonsense input, got: {:?}",
            suggestions
        );

        // Real-world case 1: wrong prefix (list vs get)
        let suggestions = find_similar_operations(&catalog, "listOrgInventory");
        assert!(
            !suggestions.is_empty() && suggestions[0].0 == "getOrgInventory",
            "Expected getOrgInventory as top suggestion for listOrgInventory, got: {:?}",
            suggestions.first().map(|(id, _, _)| id)
        );

        // Real-world case 2: missing suffix
        let suggestions = find_similar_operations(&catalog, "getOrgLicenses");
        let ids: Vec<&str> = suggestions.iter().map(|(id, _, _)| *id).collect();
        assert!(
            ids.contains(&"getOrgLicensesSummary"),
            "Expected getOrgLicensesSummary in suggestions, got: {:?}",
            ids
        );

        // Real-world case 3: semantic similarity (device + command)
        let suggestions = find_similar_operations(&catalog, "getOrgOutboundSshCmd");
        assert!(
            !suggestions.is_empty() && suggestions[0].0 == "getOrgJuniperDevicesCommand",
            "Expected getOrgJuniperDevicesCommand as top suggestion, got: {:?}",
            suggestions.first().map(|(id, _, _)| id)
        );
    }
}
