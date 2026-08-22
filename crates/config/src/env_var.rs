// Environment variable names, kept together so the set is auditable at a glance.
//
// The build script includes this file directly, so it must stay dependency-free:
// constants only.

pub const SIGNING_KEY: &str = "SERVICES_KEY_AICHAT";
pub const KEY_ID: &str = "BRAVE_SERVICES_KEY_ID";
pub const ENDPOINT: &str = "BRAVE_AI_CHAT_ENDPOINT";
/// Host for the premium tier, used once a subscription has been imported.
///
/// A separate variable rather than a prefix swap on ENDPOINT: the two are independent
/// deployments, and deriving one host from another by string substitution would break
/// the moment either name changed.
pub const PREMIUM_ENDPOINT: &str = "BRAVE_AI_CHAT_PREMIUM_ENDPOINT";
pub const MODEL: &str = "MODEL";

/// Every name a build may bake in, in the order `doctor` reports them.
pub const ALL: [&str; 5] = [SIGNING_KEY, KEY_ID, ENDPOINT, PREMIUM_ENDPOINT, MODEL];

/// Names a build must have.
///
/// MODEL is absent because it has a default. PREMIUM_ENDPOINT is absent because a build
/// without it still works for everyone who has not imported a subscription.
pub const REQUIRED: [&str; 3] = [SIGNING_KEY, KEY_ID, ENDPOINT];

/// Set to `1` to build without configuration, producing a binary that must be given
/// the variables at run time.
pub const ALLOW_UNCONFIGURED_BUILD: &str = "BUA_ALLOW_UNCONFIGURED_BUILD";
