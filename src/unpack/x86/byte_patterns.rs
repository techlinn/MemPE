pub(crate) const fn hex(pattern: &'static str) -> &'static str {
    let text = pattern.as_bytes();
    let mut at = 0;
    let mut tokens = 0;

    while at < text.len() {
        if text[at].is_ascii_whitespace() {
            at += 1;
            continue;
        }

        assert!(at + 1 < text.len(), "pattern ends inside a byte");
        let pair = (text[at], text[at + 1]);
        let wildcard = pair.0 == b'?' && pair.1 == b'?';
        assert!(
            wildcard || (pair.0.is_ascii_hexdigit() && pair.1.is_ascii_hexdigit()),
            "pattern token is neither two hex digits nor ??"
        );
        let ends = at + 2 == text.len() || text[at + 2].is_ascii_whitespace();
        assert!(ends, "pattern token is longer than one byte");

        at += 2;
        tokens += 1;
    }

    assert!(tokens > 0, "empty pattern");
    pattern // in a const, a typo fails the build
}

pub(crate) fn find_pattern(haystack: &[u8], pattern: &str) -> Option<usize> {
    find_patterns(haystack, pattern).next()
}

pub(crate) fn pattern_at(bytes: &[u8], at: usize, pattern: &str) -> bool {
    let length = pattern.split_whitespace().count();
    bytes
        .get(at..at.saturating_add(length))
        .is_some_and(|code| find_pattern(code, pattern) == Some(0))
}

pub(crate) fn find_patterns<'a>(
    haystack: &'a [u8],
    pattern: &str,
) -> impl Iterator<Item = usize> + 'a {
    let expected = pattern
        .split_whitespace()
        .map(|token| match token {
            "??" => Some(None),
            hex => u8::from_str_radix(hex, 16).ok().map(Some),
        })
        .collect::<Option<Vec<_>>>()
        .unwrap_or_default();
    let usable = !expected.is_empty();
    haystack
        .windows(expected.len().max(1))
        .enumerate()
        .filter(move |(_, window)| {
            usable
                && window
                    .iter()
                    .zip(&expected)
                    .all(|(byte, wanted)| wanted.is_none_or(|wanted| wanted == *byte))
        })
        .map(|(at, _)| at)
}
