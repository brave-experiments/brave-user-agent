//! Finding the Leo order id in a local Brave install.
//!
//! # Where the subscription state actually lives
//!
//! Not in the profile directory, which is the natural guess and is wrong. `skus.state` began as a
//! profile preference and was moved to the browser-wide `Local State` file (brave-core's
//! `MigrateSkusSettings`), so a current install has it there and an empty `skus.state` in
//! `Default/Preferences`. Both are read here, `Local State` first, because an install that has
//! not launched since the migration still has the old copy.
//!
//! It is stored in the clear. Chromium encrypts cookies and passwords with OSCrypt, which on
//! macOS means a Keychain prompt, but `skus.state` is a plain preference and nothing under
//! brave-core's `components/skus` references OSCrypt at all. So reading it needs no Keychain
//! access and no user prompt.
//!
//! The value is a JSON string *inside* the preference JSON, so it is parsed twice. That is not a
//! quirk of this reader: the SKU SDK treats the pref as opaque key/value storage and serialises
//! its own state into it.
//!
//! # Only the order id leaves this module
//!
//! The file also holds the browser's own signed credentials, and they are deliberately not read.
//! Spending them would consume a device slot the browser is using. Everything else this import
//! needs, the item id and how many credentials to ask for, comes from the server in response to
//! the order id, which is also more current than the profile's copy after a renewal.

use std::path::PathBuf;

/// Which installed Brave a subscription is being imported from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Channel {
    Stable,
    Beta,
    Nightly,
}

impl Channel {
    /// Parse a channel name as a person would type it.
    pub fn parse(name: &str) -> Option<Self> {
        match name.trim().to_ascii_lowercase().as_str() {
            "stable" | "release" => Some(Self::Stable),
            "beta" => Some(Self::Beta),
            "nightly" | "canary" => Some(Self::Nightly),
            _ => None,
        }
    }

    /// The suffix Brave appends to its data directory for this channel.
    ///
    /// Stable has none, which is why this is not simply the channel's name.
    fn directory_suffix(self) -> &'static str {
        match self {
            Self::Stable => "",
            Self::Beta => "-Beta",
            Self::Nightly => "-Nightly",
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Stable => "stable",
            Self::Beta => "beta",
            Self::Nightly => "nightly",
        }
    }

    /// The install's user data directory, or `None` on a platform with no local Brave to read.
    ///
    /// Windows is absent because this repository does not support it, not because the file would
    /// be unreadable there.
    pub fn user_data_dir(self) -> Option<PathBuf> {
        let home = PathBuf::from(std::env::var_os("HOME")?);
        let suffix = self.directory_suffix();

        #[cfg(target_os = "macos")]
        {
            Some(
                home.join("Library/Application Support/BraveSoftware")
                    .join(format!("Brave-Browser{suffix}")),
            )
        }

        #[cfg(target_os = "linux")]
        {
            // Brave follows the XDG base directory spec, so an overridden config home wins.
            let config = std::env::var_os("XDG_CONFIG_HOME")
                .map(PathBuf::from)
                .filter(|p| p.is_absolute())
                .unwrap_or_else(|| home.join(".config"));
            Some(
                config
                    .join("BraveSoftware")
                    .join(format!("Brave-Browser{suffix}")),
            )
        }

        #[cfg(not(any(target_os = "macos", target_os = "linux")))]
        {
            let _ = (home, suffix);
            None
        }
    }

    /// The files that may hold `skus.state`, in the order they should be tried.
    ///
    /// `Local State` is where a current install keeps it; the profile preference file is the
    /// pre-migration location and is only a fallback.
    pub fn state_files(self) -> Vec<PathBuf> {
        match self.user_data_dir() {
            Some(dir) => vec![
                dir.join("Local State"),
                dir.join("Default").join("Preferences"),
            ],
            None => Vec::new(),
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum ProfileError {
    /// No local Brave install for this channel.
    NotInstalled { channel: Channel },
    /// This platform has no Brave install this can read.
    UnsupportedPlatform,
    /// The install is present but holds no Leo subscription.
    NoSubscription { channel: Channel },
    /// A Leo order exists but is not in a state that can be imported.
    NotPaid { channel: Channel, status: String },
    /// The state was found but could not be understood.
    Malformed { detail: String },
}

impl std::fmt::Display for ProfileError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotInstalled { channel } => write!(
                f,
                "no Brave {} install found; nothing to import from",
                channel.as_str()
            ),
            Self::UnsupportedPlatform => f.write_str(
                "importing from a local Brave install is only supported on macOS and Linux",
            ),
            Self::NoSubscription { channel } => write!(
                f,
                "Brave {} has no Leo Premium subscription; sign in to Leo there first",
                channel.as_str()
            ),
            Self::NotPaid { channel, status } => write!(
                f,
                "the Leo subscription in Brave {} is '{}', not paid",
                channel.as_str(),
                status
            ),
            Self::Malformed { detail } => {
                write!(f, "could not read the subscription state: {detail}")
            }
        }
    }
}

impl std::error::Error for ProfileError {}

/// Find the order id of the Leo subscription in a local install.
pub fn find_leo_order(channel: Channel) -> Result<String, ProfileError> {
    let files = channel.state_files();
    if files.is_empty() {
        return Err(ProfileError::UnsupportedPlatform);
    }

    let mut saw_a_file = false;
    let mut outcome = None;

    for path in files {
        let Ok(text) = std::fs::read_to_string(&path) else {
            continue;
        };
        saw_a_file = true;

        match leo_order_in_preferences(&text) {
            // The first file with a usable order wins.
            Ok(order_id) => return Ok(order_id),
            // A file may exist with the pref absent, migrated away, or empty. That is not a
            // failure while another candidate is left to try, so the first real complaint is
            // remembered and only reported if nothing better turns up.
            Err(err) => outcome = outcome.or(Some(err)),
        }
    }

    if !saw_a_file {
        return Err(ProfileError::NotInstalled { channel });
    }

    Err(match outcome {
        Some(OrderLookupError::Malformed { detail }) => ProfileError::Malformed { detail },
        Some(OrderLookupError::NotPaid { status }) => ProfileError::NotPaid { channel, status },
        _ => ProfileError::NoSubscription { channel },
    })
}

/// Why an individual preferences file yielded no order.
#[derive(Debug, PartialEq, Eq)]
enum OrderLookupError {
    /// No `skus.state`, or it holds no Leo order.
    Absent,
    NotPaid {
        status: String,
    },
    Malformed {
        detail: String,
    },
}

/// Extract the Leo order id from the text of a Chromium preferences file.
///
/// Separate from the filesystem so the parsing is testable against fixtures rather than against
/// whatever happens to be installed.
fn leo_order_in_preferences(text: &str) -> Result<String, OrderLookupError> {
    let root: serde_json::Value =
        serde_json::from_str(text).map_err(|e| OrderLookupError::Malformed {
            detail: format!("not valid JSON: {e}"),
        })?;

    let state = root
        .get("skus")
        .and_then(|skus| skus.get("state"))
        .and_then(serde_json::Value::as_object)
        .ok_or(OrderLookupError::Absent)?;

    let mut outcome = None;

    // Keyed by environment, "skus:production" alongside a possible "skus:staging". Every
    // environment is searched because a developer build may only have the staging one, and the
    // order id is all that is taken either way.
    for value in state.values() {
        // Each value is itself a JSON document: the SDK serialises its state into an opaque
        // string, so the pref holds JSON inside JSON.
        let Some(serialised) = value.as_str() else {
            continue;
        };
        let Ok(inner) = serde_json::from_str::<serde_json::Value>(serialised) else {
            continue;
        };
        let Some(orders) = inner.get("orders").and_then(serde_json::Value::as_object) else {
            continue;
        };

        for order in orders.values() {
            if !is_leo_order(order) {
                continue;
            }

            let status = order
                .get("status")
                .and_then(serde_json::Value::as_str)
                .unwrap_or_default();
            if status != "paid" {
                outcome = outcome.or(Some(OrderLookupError::NotPaid {
                    status: status.to_string(),
                }));
                continue;
            }

            match order.get("id").and_then(serde_json::Value::as_str) {
                // Checked before use because it becomes part of a request path. A value that is
                // not a plain uuid is refused rather than sent, so nothing in this file can
                // steer the request somewhere else.
                Some(id) if is_uuid(id) => return Ok(id.to_string()),
                Some(_) => {
                    outcome = outcome.or(Some(OrderLookupError::Malformed {
                        detail: "the order id is not a uuid".to_string(),
                    }))
                }
                None => {
                    outcome = outcome.or(Some(OrderLookupError::Malformed {
                        detail: "the order has no id".to_string(),
                    }))
                }
            }
        }
    }

    Err(outcome.unwrap_or(OrderLookupError::Absent))
}

/// Whether an order is the Leo one.
///
/// Matched on `location` and on any item's `sku`, since the same store holds VPN and Search
/// Premium orders and either field alone has been enough to identify a product at some point.
fn is_leo_order(order: &serde_json::Value) -> bool {
    if order.get("location").and_then(serde_json::Value::as_str) == Some(crate::LEO_LOCATION) {
        return true;
    }

    order
        .get("items")
        .and_then(serde_json::Value::as_array)
        .is_some_and(|items| {
            items.iter().any(|item| {
                item.get("sku").and_then(serde_json::Value::as_str) == Some(crate::LEO_SKU)
            })
        })
}

/// Whether a string is a plain hyphenated uuid.
///
/// Written out rather than pulled from a crate because the only question is whether this is safe
/// to put in a URL path, and that is a handful of character checks.
fn is_uuid(value: &str) -> bool {
    const GROUPS: [usize; 5] = [8, 4, 4, 4, 12];

    let mut groups = value.split('-');
    for width in GROUPS {
        match groups.next() {
            Some(group) if group.len() == width && group.bytes().all(|b| b.is_ascii_hexdigit()) => {
            }
            _ => return false,
        }
    }
    groups.next().is_none()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A preferences file as a current install writes it: the pref in `Local State`, holding a
    /// JSON string that itself holds the orders.
    fn preferences_with(inner: serde_json::Value) -> String {
        serde_json::json!({
            "skus": { "state": { "skus:production": inner.to_string() } }
        })
        .to_string()
    }

    fn leo_order(id: &str, status: &str) -> serde_json::Value {
        serde_json::json!({
            "orders": {
                id: {
                    "id": id,
                    "status": status,
                    "location": "leo.brave.com",
                    "merchant_id": "brave.com",
                    "items": [{
                        "id": "b7114ccc-b3a5-4951-9a5d-8b7a28731111",
                        "sku": "brave-leo-premium",
                        "credential_type": "time-limited-v2"
                    }]
                }
            }
        })
    }

    #[test]
    fn channel_names_are_recognised_as_a_person_would_type_them() {
        assert_eq!(Channel::parse("stable"), Some(Channel::Stable));
        assert_eq!(Channel::parse("Beta"), Some(Channel::Beta));
        assert_eq!(Channel::parse("  NIGHTLY  "), Some(Channel::Nightly));
        assert_eq!(Channel::parse("dev"), None);
    }

    /// Stable's directory has no suffix, so deriving the path from the channel name would look
    /// for "Brave-Browser-stable" and find nothing.
    #[test]
    fn the_stable_channel_directory_carries_no_suffix() {
        assert_eq!(Channel::Stable.directory_suffix(), "");
        assert_eq!(Channel::Beta.directory_suffix(), "-Beta");
    }

    /// `Local State` must be consulted before the profile preference file, because a migrated
    /// install leaves an empty pref behind in the latter.
    #[test]
    fn the_browser_wide_state_file_is_preferred_over_the_profile_one() {
        let files = Channel::Stable.state_files();
        if files.is_empty() {
            return; // unsupported platform; covered by its own test
        }
        assert!(files[0].ends_with("Local State"));
        assert!(files[1].ends_with("Default/Preferences"));
    }

    #[test]
    fn finds_the_order_id_of_a_paid_leo_subscription() {
        let id = "3cc63766-991f-4c87-984e-ecdea77c86d8";
        let text = preferences_with(leo_order(id, "paid"));
        assert_eq!(leo_order_in_preferences(&text).unwrap(), id);
    }

    /// The pref holds JSON inside JSON. A reader that parsed only the outer layer would find the
    /// state present and conclude there was no subscription.
    #[test]
    fn the_doubly_encoded_state_is_parsed_through_both_layers() {
        let id = "3cc63766-991f-4c87-984e-ecdea77c86d8";
        let text = preferences_with(leo_order(id, "paid"));
        // The orders really are nested inside a string, not an object.
        let root: serde_json::Value = serde_json::from_str(&text).unwrap();
        assert!(root["skus"]["state"]["skus:production"].is_string());
        assert_eq!(leo_order_in_preferences(&text).unwrap(), id);
    }

    /// VPN and Search Premium subscriptions live in the same store, so the Leo order has to be
    /// picked out rather than assumed to be the only one.
    ///
    /// The Leo id sorts last of the three, so a reader that returned whichever order it happened
    /// to see first would fail here rather than pass by luck of the ordering.
    #[test]
    fn picks_leo_out_of_a_store_holding_other_subscriptions() {
        let leo = "ffffffff-991f-4c87-984e-ecdea77c86d8";
        let text = preferences_with(serde_json::json!({
            "orders": {
                "aaaaaaaa-63bc-4fa7-bf93-2b4b03b7ef7e": {
                    "id": "aaaaaaaa-63bc-4fa7-bf93-2b4b03b7ef7e",
                    "status": "paid",
                    "location": "vpn.brave.com",
                    "items": [{ "sku": "brave-vpn-premium" }]
                },
                "bbbbbbbb-b943-43b6-a252-770379631508": {
                    "id": "bbbbbbbb-b943-43b6-a252-770379631508",
                    "status": "paid",
                    "location": "search.brave.com",
                    "items": [{ "sku": "brave-search-premium" }]
                },
                leo: {
                    "id": leo,
                    "status": "paid",
                    "location": "leo.brave.com",
                    "items": [{ "sku": "brave-leo-premium" }]
                }
            }
        }));
        assert_eq!(leo_order_in_preferences(&text).unwrap(), leo);
    }

    #[test]
    fn a_store_with_only_other_subscriptions_reports_no_leo_subscription() {
        let text = preferences_with(serde_json::json!({
            "orders": {
                "aaaaaaaa-63bc-4fa7-bf93-2b4b03b7ef7e": {
                    "id": "aaaaaaaa-63bc-4fa7-bf93-2b4b03b7ef7e",
                    "status": "paid",
                    "location": "vpn.brave.com",
                    "items": [{ "sku": "brave-vpn-premium" }]
                }
            }
        }));
        assert_eq!(
            leo_order_in_preferences(&text).unwrap_err(),
            OrderLookupError::Absent
        );
    }

    /// An unpaid order must be reported as such rather than as an absent subscription: the two
    /// suggest completely different fixes.
    #[test]
    fn an_unpaid_order_is_distinguished_from_a_missing_one() {
        let text = preferences_with(leo_order(
            "3cc63766-991f-4c87-984e-ecdea77c86d8",
            "canceled",
        ));
        assert_eq!(
            leo_order_in_preferences(&text).unwrap_err(),
            OrderLookupError::NotPaid {
                status: "canceled".to_string()
            }
        );
    }

    /// An install that has never held a subscription has the pref registered but empty.
    #[test]
    fn an_empty_state_reports_no_subscription() {
        let text = serde_json::json!({ "skus": { "state": {} } }).to_string();
        assert_eq!(
            leo_order_in_preferences(&text).unwrap_err(),
            OrderLookupError::Absent
        );
    }

    /// The post-migration profile file: valid preferences, no skus key at all.
    #[test]
    fn preferences_without_any_subscription_state_report_no_subscription() {
        let text = serde_json::json!({ "profile": { "name": "Default" } }).to_string();
        assert_eq!(
            leo_order_in_preferences(&text).unwrap_err(),
            OrderLookupError::Absent
        );
    }

    #[test]
    fn a_truncated_preferences_file_is_reported_as_malformed() {
        let err = leo_order_in_preferences("{\"skus\": {\"state\":").unwrap_err();
        assert!(matches!(err, OrderLookupError::Malformed { .. }));
    }

    /// The order id becomes part of a request path, so a value that is not a uuid is refused
    /// rather than sent. Nothing in this file gets to decide where the request goes.
    #[test]
    fn an_order_id_that_is_not_a_uuid_is_refused_rather_than_used() {
        let text = preferences_with(leo_order("../../v1/orders/someone-elses", "paid"));
        assert!(matches!(
            leo_order_in_preferences(&text).unwrap_err(),
            OrderLookupError::Malformed { .. }
        ));
    }

    #[test]
    fn uuids_are_recognised_and_near_misses_are_not() {
        assert!(is_uuid("3cc63766-991f-4c87-984e-ecdea77c86d8"));
        assert!(!is_uuid("3cc63766991f4c87984eecdea77c86d8"));
        assert!(!is_uuid("3cc63766-991f-4c87-984e-ecdea77c86d"));
        assert!(!is_uuid("3cc63766-991f-4c87-984e-ecdea77c86d8-extra"));
        assert!(!is_uuid("3cc63766-991f-4c87-984e-ecdea77c86dg"));
        assert!(!is_uuid("../../etc/passwd"));
        assert!(!is_uuid(""));
    }

    /// A staging-only developer build has no production entry, and the order id is all that is
    /// taken from either, so every environment present is searched.
    #[test]
    fn an_order_in_a_non_production_environment_is_still_found() {
        let id = "3cc63766-991f-4c87-984e-ecdea77c86d8";
        let text = serde_json::json!({
            "skus": { "state": { "skus:staging": leo_order(id, "paid").to_string() } }
        })
        .to_string();
        assert_eq!(leo_order_in_preferences(&text).unwrap(), id);
    }

    /// The browser's own signed credentials are in the same file and must not be what this
    /// reads: spending them would consume the browser's device slot.
    #[test]
    fn the_browsers_own_credentials_are_not_read() {
        let id = "3cc63766-991f-4c87-984e-ecdea77c86d8";
        let mut inner = leo_order(id, "paid");
        inner["credentials"] = serde_json::json!({
            "items": {
                "b7114ccc-b3a5-4951-9a5d-8b7a28731111": {
                    "state": "ActiveCredentials",
                    "unblinded_creds": [{ "unblinded_cred": "SECRET-DEVICE-TOKEN", "spent": false }]
                }
            }
        });
        let text = preferences_with(inner);
        // Only the order id comes back out, so the stored credential cannot leak through it.
        assert_eq!(leo_order_in_preferences(&text).unwrap(), id);
    }
}
