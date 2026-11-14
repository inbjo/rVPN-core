//! Build-time imported GFWList domain rules. Runtime needs no network, disk
//! access or additional settings.
use std::collections::HashSet;

#[derive(Debug, Clone, Default, serde::Deserialize)]
pub struct Rules {
    pub proxy: HashSet<String>,
    pub exceptions: HashSet<String>,
    pub skipped: usize,
}

fn matches(host: &str, rules: &HashSet<String>) -> bool {
    let host = host.trim_end_matches('.').to_ascii_lowercase();
    rules.contains(&host)
        || host
            .match_indices('.')
            .any(|(i, _)| rules.contains(&host[i + 1..]))
}

impl Rules {
    pub fn forces_proxy(&self, host: &str) -> bool {
        matches(host, &self.proxy) && !matches(host, &self.exceptions)
    }
}

pub fn builtin() -> &'static Rules {
    static RULES: std::sync::OnceLock<Rules> = std::sync::OnceLock::new();
    RULES.get_or_init(|| {
        #[cfg(feature = "builtin-domains")]
        {
            serde_json::from_slice(include_bytes!("../data/gfwlist-rules.json"))
                .expect("validated build-time GFWList snapshot")
        }
        #[cfg(not(feature = "builtin-domains"))]
        {
            Rules::default()
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn domain_boundaries_and_exceptions_are_preserved() {
        let rules = Rules {
            proxy: HashSet::from(["example.com".into()]),
            exceptions: HashSet::from(["safe.example.com".into()]),
            skipped: 0,
        };
        assert!(rules.forces_proxy("WWW.EXAMPLE.COM."));
        assert!(!rules.forces_proxy("child.safe.example.com"));
        assert!(!rules.forces_proxy("notexample.com"));
    }

    #[cfg(feature = "builtin-domains")]
    #[test]
    fn snapshot_is_embedded_and_ready_without_downloads_or_configuration() {
        let rules = builtin();
        assert!(rules.proxy.len() > 1000);
        assert!(rules.forces_proxy("www.youtube.com"));
        assert!(rules.forces_proxy("www.google.com"));
        let source: serde_json::Value =
            serde_json::from_slice(include_bytes!("../data/gfwlist-source.json")).unwrap();
        assert_eq!(source["counts"]["proxy"], rules.proxy.len());
        assert_eq!(source["counts"]["exceptions"], rules.exceptions.len());
        assert_eq!(source["counts"]["skipped"], rules.skipped);
    }
}
