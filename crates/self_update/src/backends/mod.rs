/*!
Collection of modules supporting various release distribution backends
*/

pub mod github;

/// Search for the first "rel" link-header uri in a full link header string.
/// Seems like reqwest/hyper threw away their link-header parser implementation...
///
/// ex:
/// `Link: <https://api.github.com/resource?page=2>; rel="next"`
/// `Link: <https://gitlab.com/api/v4/projects/13083/releases?id=13083&page=2&per_page=20>; rel="next"`
///
/// https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Link
/// header values may contain multiple values separated by commas
/// `Link: <https://place.com>; rel="next", <https://wow.com>; rel="next"`
pub(crate) fn find_rel_next_link(link_str: &str) -> Option<&str> {
    for link in link_str.split(',') {
        let mut uri = None;
        let mut is_rel_next = false;
        for part in link.split(';') {
            let part = part.trim();
            if part.starts_with('<') && part.ends_with('>') {
                uri = Some(part.trim_start_matches('<').trim_end_matches('>'));
            } else if part.starts_with("rel=") {
                let part = part
                    .trim_start_matches("rel=")
                    .trim_end_matches('"')
                    .trim_start_matches('"');
                if part == "next" {
                    is_rel_next = true;
                }
            }

            if is_rel_next && uri.is_some() {
                return uri;
            }
        }
    }
    None
}
