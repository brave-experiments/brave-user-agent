//! Configuration read from the environment, populated by direnv, falling back to
//! whatever was baked in at build time.
//!
//! The signing key is wrapped in [`Secret`] so it cannot be printed. That matters
//! more than usual here: this is a public repository, and the natural debugging
//! reflex, dumping the config, would otherwise put a live credential in a log or
//! an issue report.

use std::env;
use std::fmt;

/// Environment variable names, kept together so the set is auditable at a glance.
pub mod env_var {
    include!("env_var.rs");
}

mod obfuscate;

include!(concat!(env!("OUT_DIR"), "/baked.rs"));

/// The server treats an unrecognised model as `automatic`, so that is also our
/// default rather than pinning a name that may silently stop existing.
pub const DEFAULT_MODEL: &str = "automatic";

/// A value that must not be printed.
///
/// `Debug` and `Display` are deliberately redacting, and the inner value is only
/// reachable through [`Secret::expose`], a name chosen so that reading a credential
/// is visible at the call site during review.
#[derive(Clone, PartialEq, Eq)]
pub struct Secret(String);

impl Secret {
    pub fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }

    /// Read the secret. Call sites should be rare and obvious.
    pub fn expose(&self) -> &str {
        &self.0
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl fmt::Debug for Secret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Secret(<redacted>)")
    }
}

impl fmt::Display for Secret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("<redacted>")
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum ConfigError {
    Missing(&'static str),
    Empty(&'static str),
    InvalidEndpoint { value: String },
}

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Missing(name) => write!(
                f,
                "{name} is not set and was not built in; copy .envrc.example to .envrc and run `direnv allow`"
            ),
            Self::Empty(name) => write!(f, "{name} is set but empty"),
            Self::InvalidEndpoint { value } => write!(
                f,
                "endpoint must start with http:// or https://, got '{value}'"
            ),
        }
    }
}

impl std::error::Error for ConfigError {}

/// Everything needed to talk to the aichat backend.
#[derive(Debug, Clone)]
pub struct Config {
    /// HMAC signing key. Never transmitted; used only to sign the request digest.
    pub signing_key: Secret,
    /// Key id sent in the Authorization header. The server derives its copy of the
    /// signing key from a master seed plus this id, so the two are a matched pair.
    pub key_id: String,
    /// Base URL. The API path is appended by the client.
    pub endpoint: String,
    /// Base URL for the premium tier, when this build has one.
    ///
    /// `None` leaves premium unavailable, which is the right outcome for a build that was never
    /// given the host: falling back to the free endpoint with a subscription credential attached
    /// would send the credential somewhere it does not belong.
    pub premium_endpoint: Option<String>,
    /// Model to request. The server may substitute a different one.
    pub model: String,
}

/// A value captured when this binary was built, or `None` if the build had none.
///
/// The masking is undone here rather than at startup so a credential is materialised
/// only for the variable actually being read.
fn built_in(name: &str) -> Option<String> {
    let (_, masked) = BAKED.iter().find(|(baked, _)| *baked == name)?;
    String::from_utf8(obfuscate::mask(masked)).ok()
}

/// Pick between what the environment says and what the build baked in.
fn resolve(
    name: &str,
    from_env: Option<String>,
    baked: impl Fn(&str) -> Option<String>,
) -> Option<String> {
    match from_env {
        Some(value) if !value.trim().is_empty() => Some(value),
        // A placeholder .envrc leaves a variable blank, which is not a request to
        // override, so a built-in value still applies. With none, the blank is handed
        // on so the error reports it as empty rather than missing.
        blank => baked(name).or(blank),
    }
}

impl Config {
    /// Read configuration from the process environment, falling back to the values
    /// built into this binary.
    ///
    /// The environment wins, so a developer can point a released binary at a local
    /// backend without rebuilding it.
    pub fn from_env() -> Result<Self, ConfigError> {
        Self::from_lookup(|key| resolve(key, env::var(key).ok(), built_in))
    }

    /// Read configuration from an arbitrary lookup, so tests need not mutate global
    /// process state.
    pub fn from_lookup(lookup: impl Fn(&str) -> Option<String>) -> Result<Self, ConfigError> {
        let required = |name: &'static str| -> Result<String, ConfigError> {
            match lookup(name) {
                None => Err(ConfigError::Missing(name)),
                Some(v) if v.trim().is_empty() => Err(ConfigError::Empty(name)),
                Some(v) => Ok(v),
            }
        };

        let signing_key = Secret::new(required(env_var::SIGNING_KEY)?);
        let key_id = required(env_var::KEY_ID)?;
        let endpoint = required(env_var::ENDPOINT)?;

        if !(endpoint.starts_with("https://") || endpoint.starts_with("http://")) {
            return Err(ConfigError::InvalidEndpoint { value: endpoint });
        }

        let model = lookup(env_var::MODEL)
            .filter(|m| !m.trim().is_empty())
            .unwrap_or_else(|| DEFAULT_MODEL.to_string());

        // A premium host that is present but malformed is dropped rather than rejected: it only
        // matters to someone who has imported a subscription, and failing every run over it would
        // punish everyone else.
        let premium_endpoint = lookup(env_var::PREMIUM_ENDPOINT)
            .map(|value| value.trim().to_string())
            .filter(|value| value.starts_with("https://") || value.starts_with("http://"))
            .map(|value| value.trim_end_matches('/').to_string());

        Ok(Self {
            signing_key,
            key_id,
            endpoint: endpoint.trim_end_matches('/').to_string(),
            premium_endpoint,
            model,
        })
    }

    /// Full URL for the OpenAI-compatible chat completions endpoint.
    ///
    /// This is the v2 API: the version is inferred from the path by the server, so
    /// there is no `/v2/` route to construct.
    pub fn chat_completions_url(&self) -> String {
        format!("{}/v1/chat/completions", self.endpoint)
    }

    /// The same endpoint on the premium host, when this build has one.
    pub fn premium_chat_completions_url(&self) -> Option<String> {
        self.premium_endpoint
            .as_ref()
            .map(|base| format!("{base}/v1/chat/completions"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn complete_env(key: &str) -> Option<String> {
        match key {
            env_var::SIGNING_KEY => Some("test-signing-key".into()),
            env_var::KEY_ID => Some("test-key-id".into()),
            env_var::ENDPOINT => Some("https://example.invalid".into()),
            _ => None,
        }
    }

    #[test]
    fn reads_a_complete_environment() {
        let config = Config::from_lookup(complete_env).unwrap();
        assert_eq!(config.key_id, "test-key-id");
        assert_eq!(config.signing_key.expose(), "test-signing-key");
    }

    #[test]
    fn model_defaults_to_automatic() {
        let config = Config::from_lookup(complete_env).unwrap();
        assert_eq!(config.model, DEFAULT_MODEL);
    }

    #[test]
    fn model_can_be_overridden() {
        let config = Config::from_lookup(|k| match k {
            env_var::MODEL => Some("some-pinned-model".into()),
            other => complete_env(other),
        })
        .unwrap();
        assert_eq!(config.model, "some-pinned-model");
    }

    /// An empty MODEL should fall back rather than sending "" and being silently
    /// reset by the server.
    #[test]
    fn an_empty_model_falls_back_to_the_default() {
        let config = Config::from_lookup(|k| match k {
            env_var::MODEL => Some("   ".into()),
            other => complete_env(other),
        })
        .unwrap();
        assert_eq!(config.model, DEFAULT_MODEL);
    }

    #[test]
    fn a_missing_signing_key_is_an_error() {
        let err = Config::from_lookup(|k| match k {
            env_var::SIGNING_KEY => None,
            other => complete_env(other),
        })
        .unwrap_err();
        assert_eq!(err, ConfigError::Missing(env_var::SIGNING_KEY));
    }

    /// A placeholder .envrc leaves variables present but blank, which must not be
    /// mistaken for a real credential.
    #[test]
    fn an_empty_signing_key_is_an_error() {
        let err = Config::from_lookup(|k| match k {
            env_var::SIGNING_KEY => Some(String::new()),
            other => complete_env(other),
        })
        .unwrap_err();
        assert_eq!(err, ConfigError::Empty(env_var::SIGNING_KEY));
    }

    #[test]
    fn a_missing_key_id_is_an_error() {
        let err = Config::from_lookup(|k| match k {
            env_var::KEY_ID => None,
            other => complete_env(other),
        })
        .unwrap_err();
        assert_eq!(err, ConfigError::Missing(env_var::KEY_ID));
    }

    #[test]
    fn an_endpoint_without_a_scheme_is_rejected() {
        let err = Config::from_lookup(|k| match k {
            env_var::ENDPOINT => Some("ai-chat.example.invalid".into()),
            other => complete_env(other),
        })
        .unwrap_err();
        assert!(matches!(err, ConfigError::InvalidEndpoint { .. }));
    }

    #[test]
    fn a_trailing_slash_does_not_double_up_in_the_url() {
        let config = Config::from_lookup(|k| match k {
            env_var::ENDPOINT => Some("https://example.invalid/".into()),
            other => complete_env(other),
        })
        .unwrap();
        assert_eq!(
            config.chat_completions_url(),
            "https://example.invalid/v1/chat/completions"
        );
    }

    #[test]
    fn builds_the_openai_compatible_url() {
        let config = Config::from_lookup(complete_env).unwrap();
        assert_eq!(
            config.chat_completions_url(),
            "https://example.invalid/v1/chat/completions"
        );
    }

    /// A local development endpoint over plain http is allowed.
    #[test]
    fn http_endpoints_are_allowed_for_local_development() {
        let config = Config::from_lookup(|k| match k {
            env_var::ENDPOINT => Some("http://127.0.0.1:8000".into()),
            other => complete_env(other),
        })
        .unwrap();
        assert_eq!(
            config.chat_completions_url(),
            "http://127.0.0.1:8000/v1/chat/completions"
        );
    }

    /// The premium tier is a separate deployment, so its URL must come from its own variable
    /// rather than being derived from the free host.
    #[test]
    fn the_premium_endpoint_builds_its_own_url() {
        let config = Config::from_lookup(|k| match k {
            env_var::PREMIUM_ENDPOINT => Some("https://premium.invalid".into()),
            other => complete_env(other),
        })
        .unwrap();
        assert_eq!(
            config.premium_chat_completions_url().as_deref(),
            Some("https://premium.invalid/v1/chat/completions")
        );
    }

    /// A build without the premium host must report premium as unavailable rather than quietly
    /// using the free endpoint, which would send a subscription credential to the wrong host.
    #[test]
    fn a_build_without_a_premium_endpoint_has_no_premium_url() {
        let config = Config::from_lookup(complete_env).unwrap();
        assert_eq!(config.premium_endpoint, None);
        assert_eq!(config.premium_chat_completions_url(), None);
    }

    /// A blank or schemeless premium host is discarded, not turned into a request to a host with
    /// no scheme.
    #[test]
    fn a_malformed_premium_endpoint_is_discarded() {
        for value in ["", "   ", "premium.invalid"] {
            let config = Config::from_lookup(|k| match k {
                env_var::PREMIUM_ENDPOINT => Some(value.into()),
                other => complete_env(other),
            })
            .unwrap();
            assert_eq!(config.premium_endpoint, None, "accepted '{value}'");
        }
    }

    #[test]
    fn a_trailing_slash_on_the_premium_endpoint_does_not_double_up() {
        let config = Config::from_lookup(|k| match k {
            env_var::PREMIUM_ENDPOINT => Some("https://premium.invalid/".into()),
            other => complete_env(other),
        })
        .unwrap();
        assert_eq!(
            config.premium_chat_completions_url().as_deref(),
            Some("https://premium.invalid/v1/chat/completions")
        );
    }

    #[test]
    fn secrets_are_redacted_in_debug_and_display() {
        let secret = Secret::new("live-credential");
        assert_eq!(format!("{secret:?}"), "Secret(<redacted>)");
        assert_eq!(format!("{secret}"), "<redacted>");
        assert!(!format!("{secret:?}").contains("live-credential"));
    }

    /// An explicit variable must win, so a released binary can be pointed at a local
    /// backend without rebuilding it.
    #[test]
    fn the_environment_overrides_a_built_in_value() {
        let chosen = resolve(
            env_var::ENDPOINT,
            Some("http://127.0.0.1:8000".into()),
            |_| Some("https://baked.invalid".into()),
        );
        assert_eq!(chosen.as_deref(), Some("http://127.0.0.1:8000"));
    }

    /// The point of baking values in: a binary started outside the source tree has no
    /// direnv and must still be configured.
    #[test]
    fn a_built_in_value_applies_when_the_environment_is_silent() {
        let chosen = resolve(env_var::ENDPOINT, None, |_| {
            Some("https://baked.invalid".into())
        });
        assert_eq!(chosen.as_deref(), Some("https://baked.invalid"));
    }

    /// A blank variable is a placeholder, not an instruction to discard the built-in
    /// value, so it must not shadow one.
    #[test]
    fn a_blank_variable_does_not_shadow_a_built_in_value() {
        let chosen = resolve(env_var::ENDPOINT, Some("   ".into()), |_| {
            Some("https://baked.invalid".into())
        });
        assert_eq!(chosen.as_deref(), Some("https://baked.invalid"));
    }

    /// With nothing baked in, a blank must still be reported as empty rather than
    /// missing, since the two suggest different fixes.
    #[test]
    fn a_blank_variable_survives_when_nothing_was_built_in() {
        let err = Config::from_lookup(|k| match k {
            env_var::SIGNING_KEY => resolve(k, Some(String::new()), |_| None),
            other => complete_env(other),
        })
        .unwrap_err();
        assert_eq!(err, ConfigError::Empty(env_var::SIGNING_KEY));
    }

    /// Masking is what keeps a baked credential out of `strings` output, and it is
    /// only usable at all if it round-trips.
    #[test]
    fn masking_round_trips_and_does_not_leave_the_value_readable() {
        let secret = "live-credential-abc123";
        let masked = obfuscate::mask(secret.as_bytes());
        assert_ne!(masked, secret.as_bytes());
        assert_eq!(obfuscate::mask(&masked), secret.as_bytes());
    }

    /// Two values sharing a prefix must not produce a shared masked prefix, or the
    /// masking would advertise the relationship.
    #[test]
    fn values_with_a_shared_prefix_do_not_share_a_masked_prefix() {
        let one = obfuscate::mask(b"prefix-aaaa");
        let two = obfuscate::mask(b"prefix-bbbbbb");
        assert_ne!(one[0], two[0]);
    }

    /// Debug-printing the whole config is the obvious debugging reflex, so it must
    /// not leak the key.
    #[test]
    fn debugging_the_config_does_not_leak_the_key() {
        let config = Config::from_lookup(complete_env).unwrap();
        let shown = format!("{config:?}");
        assert!(!shown.contains("test-signing-key"), "leaked: {shown}");
        assert!(shown.contains("redacted"));
    }
}
