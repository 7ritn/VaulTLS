/// Returns true if `domain` matches `pattern`.
///
/// Matching rules:
/// - Patterns are compared case-insensitively after whitespace trimming.
/// - An exact pattern (e.g. `example.com`) matches only that domain.
/// - A wildcard pattern (e.g. `*.example.com`) matches exactly one DNS label
///   to the left of the suffix; it does NOT match the bare suffix itself or
///   deeper subdomains such as `a.b.example.com`.
pub fn matches_domain(pattern: &str, domain: &str) -> bool {
    let pattern = pattern.trim().to_lowercase();
    let domain = domain.trim().to_lowercase();

    if pattern.is_empty() || domain.is_empty() {
        return false;
    }

    if let Some(suffix) = pattern.strip_prefix("*.") {
        // Wildcard: domain must end with ".<suffix>" and the part before that
        // must be a single label (no dots).
        let expected_suffix = format!(".{suffix}");
        if let Some(label) = domain.strip_suffix(expected_suffix.as_str()) {
            // The remaining label must be non-empty and contain no dots.
            !label.is_empty() && !label.contains('.')
        } else {
            false
        }
    } else {
        pattern == domain
    }
}

/// Returns true if `name` is a syntactically valid DNS name per RFC 952/1123.
pub fn is_valid_dns_name(name: &str) -> bool {
    let name = name.trim();
    if name.is_empty() || name.len() > 253 {
        return false;
    }
    // Reject IPv4 literals (all-numeric labels)
    // Reject IPv6 literals (contain colons or brackets)
    if name.contains(':') || name.starts_with('[') {
        return false;
    }
    let labels: Vec<&str> = name.split('.').collect();
    if labels.iter().all(|l| l.chars().all(|c| c.is_ascii_digit())) && labels.len() == 4 {
        return false; // dotted-quad IPv4
    }
    for label in &labels {
        if label.is_empty() || label.len() > 63 {
            return false;
        }
        if label.starts_with('-') || label.ends_with('-') {
            return false;
        }
        if !label.chars().all(|c| c.is_ascii_alphanumeric() || c == '-') {
            return false;
        }
    }
    true
}

/// Returns true if every domain in `requested_domains` is permitted by at
/// least one pattern in the comma-separated `allowed_domains` list.
pub fn check_domains(allowed_domains: &str, requested_domains: &[String]) -> bool {
    if requested_domains.is_empty() {
        return false;
    }

    let patterns: Vec<&str> = allowed_domains.split(',').collect();

    requested_domains
        .iter()
        .all(|domain| patterns.iter().any(|pattern| matches_domain(pattern, domain)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exact_match_works() {
        assert!(matches_domain("example.com", "example.com"));
    }

    #[test]
    fn exact_match_no_false_positive() {
        assert!(!matches_domain("example.com", "other.com"));
        assert!(!matches_domain("example.com", "sub.example.com"));
    }

    #[test]
    fn wildcard_single_level_match() {
        assert!(matches_domain("*.example.com", "foo.example.com"));
        assert!(matches_domain("*.example.com", "bar.example.com"));
    }

    #[test]
    fn wildcard_does_not_match_deeper_subdomains() {
        assert!(!matches_domain("*.example.com", "bar.foo.example.com"));
        assert!(!matches_domain("*.example.com", "a.b.c.example.com"));
    }

    #[test]
    fn wildcard_does_not_match_bare_domain() {
        assert!(!matches_domain("*.example.com", "example.com"));
    }

    #[test]
    fn case_insensitive() {
        assert!(matches_domain("Example.COM", "example.com"));
        assert!(matches_domain("example.com", "EXAMPLE.COM"));
        assert!(matches_domain("*.Example.COM", "Foo.example.com"));
    }

    #[test]
    fn whitespace_trimming() {
        assert!(matches_domain("  example.com  ", "example.com"));
        assert!(matches_domain("example.com", "  example.com  "));
        assert!(matches_domain("  *.example.com  ", "foo.example.com"));
    }

    #[test]
    fn empty_pattern_returns_false() {
        assert!(!matches_domain("", "example.com"));
        assert!(!matches_domain("   ", "example.com"));
    }

    #[test]
    fn empty_domain_returns_false() {
        assert!(!matches_domain("example.com", ""));
        assert!(!matches_domain("example.com", "   "));
    }

    #[test]
    fn check_domains_all_match() {
        let allowed = "*.example.com,api.internal";
        let requested = vec!["foo.example.com".to_string(), "api.internal".to_string()];
        assert!(check_domains(allowed, &requested));
    }

    #[test]
    fn check_domains_one_unmatched_returns_false() {
        let allowed = "*.example.com";
        let requested = vec!["foo.example.com".to_string(), "other.net".to_string()];
        assert!(!check_domains(allowed, &requested));
    }

    #[test]
    fn check_domains_empty_requested_returns_false() {
        assert!(!check_domains("*.example.com", &[]));
    }

    #[test]
    fn check_domains_empty_allowed_returns_false() {
        let requested = vec!["foo.example.com".to_string()];
        assert!(!check_domains("", &requested));
    }

    #[test]
    fn check_domains_multiple_patterns() {
        let allowed = "*.foo.com , *.bar.com , exact.baz.com";
        let requested = vec![
            "a.foo.com".to_string(),
            "b.bar.com".to_string(),
            "exact.baz.com".to_string(),
        ];
        assert!(check_domains(allowed, &requested));
    }

    #[test]
    fn check_domains_single_domain_single_pattern() {
        assert!(check_domains("example.com", &["example.com".to_string()]));
        assert!(!check_domains("example.com", &["other.com".to_string()]));
    }

    #[test]
    fn valid_dns_names() {
        assert!(is_valid_dns_name("example.com"));
        assert!(is_valid_dns_name("foo.example.com"));
        assert!(is_valid_dns_name("foo-bar.example.com"));
        assert!(is_valid_dns_name("xn--nxasmq6b.com")); // punycode
        assert!(is_valid_dns_name("a")); // single label
    }

    #[test]
    fn invalid_dns_ipv4() {
        assert!(!is_valid_dns_name("192.168.1.1"));
        assert!(!is_valid_dns_name("10.0.0.1"));
    }

    #[test]
    fn invalid_dns_ipv6() {
        assert!(!is_valid_dns_name("::1"));
        assert!(!is_valid_dns_name("[::1]"));
        assert!(!is_valid_dns_name("2001:db8::1"));
    }

    #[test]
    fn invalid_dns_hyphen_rules() {
        assert!(!is_valid_dns_name("-example.com"));
        assert!(!is_valid_dns_name("example-.com"));
        assert!(is_valid_dns_name("ex--ample.com")); // double-hyphen mid-label is valid
    }

    #[test]
    fn invalid_dns_special_chars() {
        assert!(!is_valid_dns_name("exam ple.com")); // space
        assert!(!is_valid_dns_name("exam_ple.com")); // underscore
        assert!(!is_valid_dns_name("exam*ple.com")); // wildcard char in label
    }

    #[test]
    fn invalid_dns_empty_label() {
        assert!(!is_valid_dns_name("example..com")); // empty label
        assert!(!is_valid_dns_name(".example.com")); // leading dot
    }

    #[test]
    fn invalid_dns_too_long() {
        let long_name = "a".repeat(254);
        assert!(!is_valid_dns_name(&long_name));
    }
}
