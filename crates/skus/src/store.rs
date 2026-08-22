//! Keeping the imported credentials in the OS keychain.
//!
//! These are bearer secrets: whoever holds one can spend a request against the subscription. So
//! they go to the platform's own secret store, macOS Keychain or the Secret Service on Linux,
//! rather than to a file. A mode-0600 file would be readable by anything running as the user,
//! including any program this agent is asked to run, and would sit in a backup afterwards.
//!
//! Each channel gets its own entry, so importing from Nightly does not overwrite what was
//! imported from Stable.
//!
//! # Why the whole batch is stored, not one cookie
//!
//! A time-limited-v2 credential is single-use. Presenting one to the backend spends it, so what is
//! stored is the batch the server signed, and a request takes the next unspent one. Caching a
//! ready-made cookie value would mean replaying a spent credential on the second request.

use crate::device::Registration;

/// The keychain service every entry is filed under.
const SERVICE: &str = "bua";

#[derive(Debug)]
pub enum StoreError {
    /// Nothing has been imported for this channel yet.
    NotFound,
    /// The keychain refused, or is unavailable.
    Unavailable { detail: String },
    /// The entry exists but is not what this version writes.
    Malformed { detail: String },
    /// Every credential in the batch has been spent or has expired.
    Exhausted,
}

impl std::fmt::Display for StoreError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotFound => f.write_str("no imported Leo subscription found"),
            Self::Unavailable { detail } => {
                write!(f, "the system keychain is unavailable: {detail}")
            }
            Self::Malformed { detail } => {
                write!(f, "the stored credentials are unusable: {detail}")
            }
            Self::Exhausted => f.write_str(
                "the imported credentials are used up; run `bua import-leo-creds` again",
            ),
        }
    }
}

impl std::error::Error for StoreError {}

/// A signed credential batch, as stored.
///
/// Serialised as JSON rather than a bespoke encoding because the keychain holds an opaque string
/// either way, and a readable shape is one less thing to get wrong when the format changes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredCredentials {
    /// The order the batch belongs to, so a re-import can refresh in place.
    pub order_id: String,
    /// The item the credentials are for.
    pub item_id: String,
    /// `merchant?sku=` string the presentation signs over.
    pub issuer: String,
    /// The unblinded credentials, each usable once.
    pub credentials: Vec<Credential>,
}

/// One single-use credential.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Credential {
    /// Base64 unblinded token, from which the verification key is derived.
    pub unblinded: String,
    /// Start of the window this credential is valid in, as the server stated it.
    pub valid_from: String,
    /// End of that window.
    pub valid_to: String,
    /// Whether this one has already been presented.
    pub spent: bool,
}

impl StoredCredentials {
    /// How many credentials remain unspent.
    pub fn remaining(&self) -> usize {
        self.credentials.iter().filter(|c| !c.spent).count()
    }

    /// The index of the next credential usable at `now`.
    ///
    /// `now` is passed in rather than read from the clock so the choice is testable, and compared
    /// as a string because the server's timestamps are fixed-width ISO 8601 in UTC, which orders
    /// lexicographically. Parsing them would add a date library to compare two strings.
    pub fn next_usable(&self, now: &str) -> Option<usize> {
        self.credentials
            .iter()
            .position(|c| !c.spent && c.valid_from.as_str() <= now && now < c.valid_to.as_str())
    }
}

impl From<Registration> for StoredCredentials {
    fn from(value: Registration) -> Self {
        Self {
            order_id: value.order_id,
            item_id: value.item_id,
            issuer: value.issuer,
            credentials: value
                .credentials
                .into_iter()
                .map(|c| Credential {
                    unblinded: c.unblinded,
                    valid_from: c.valid_from,
                    valid_to: c.valid_to,
                    spent: false,
                })
                .collect(),
        }
    }
}

/// The keychain entry for a channel's credentials.
fn entry(channel: crate::Channel) -> Result<keyring::Entry, StoreError> {
    keyring::Entry::new(SERVICE, &format!("leo-premium-{}", channel.as_str())).map_err(|e| {
        StoreError::Unavailable {
            detail: e.to_string(),
        }
    })
}

/// Write a batch to the keychain, replacing whatever was there.
pub fn save(channel: crate::Channel, credentials: &StoredCredentials) -> Result<(), StoreError> {
    let encoded = encode(credentials);
    entry(channel)?
        .set_password(&encoded)
        .map_err(|e| StoreError::Unavailable {
            detail: e.to_string(),
        })
}

/// Read a channel's batch.
pub fn load(channel: crate::Channel) -> Result<StoredCredentials, StoreError> {
    let raw = match entry(channel)?.get_password() {
        Ok(raw) => raw,
        Err(keyring::Error::NoEntry) => return Err(StoreError::NotFound),
        Err(e) => {
            return Err(StoreError::Unavailable {
                detail: e.to_string(),
            });
        }
    };
    decode(&raw)
}

/// Forget a channel's batch.
pub fn clear(channel: crate::Channel) -> Result<(), StoreError> {
    match entry(channel)?.delete_credential() {
        Ok(()) | Err(keyring::Error::NoEntry) => Ok(()),
        Err(e) => Err(StoreError::Unavailable {
            detail: e.to_string(),
        }),
    }
}

fn encode(credentials: &StoredCredentials) -> String {
    serde_json::json!({
        "version": 1,
        "order_id": credentials.order_id,
        "item_id": credentials.item_id,
        "issuer": credentials.issuer,
        "credentials": credentials
            .credentials
            .iter()
            .map(|c| serde_json::json!({
                "unblinded": c.unblinded,
                "valid_from": c.valid_from,
                "valid_to": c.valid_to,
                "spent": c.spent,
            }))
            .collect::<Vec<_>>(),
    })
    .to_string()
}

fn decode(raw: &str) -> Result<StoredCredentials, StoreError> {
    let value: serde_json::Value =
        serde_json::from_str(raw).map_err(|e| StoreError::Malformed {
            detail: format!("not valid JSON: {e}"),
        })?;

    let field = |name: &str| -> Result<String, StoreError> {
        value
            .get(name)
            .and_then(serde_json::Value::as_str)
            .map(str::to_string)
            .ok_or_else(|| StoreError::Malformed {
                detail: format!("missing '{name}'"),
            })
    };

    let credentials = value
        .get("credentials")
        .and_then(serde_json::Value::as_array)
        .ok_or_else(|| StoreError::Malformed {
            detail: "missing 'credentials'".to_string(),
        })?
        .iter()
        .map(|c| {
            let text = |name: &str| {
                c.get(name)
                    .and_then(serde_json::Value::as_str)
                    .unwrap_or_default()
                    .to_string()
            };
            Credential {
                unblinded: text("unblinded"),
                valid_from: text("valid_from"),
                valid_to: text("valid_to"),
                spent: c
                    .get("spent")
                    .and_then(serde_json::Value::as_bool)
                    .unwrap_or(false),
            }
        })
        .collect::<Vec<_>>();

    if credentials.iter().any(|c| c.unblinded.is_empty()) {
        return Err(StoreError::Malformed {
            detail: "a credential has no token".to_string(),
        });
    }

    Ok(StoredCredentials {
        order_id: field("order_id")?,
        item_id: field("item_id")?,
        issuer: field("issuer")?,
        credentials,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn batch() -> StoredCredentials {
        StoredCredentials {
            order_id: "3cc63766-991f-4c87-984e-ecdea77c86d8".to_string(),
            item_id: "b7114ccc-b3a5-4951-9a5d-8b7a28731111".to_string(),
            issuer: "brave.com?sku=brave-leo-premium".to_string(),
            credentials: vec![
                Credential {
                    unblinded: "token-one".to_string(),
                    valid_from: "2026-08-22T00:00:00".to_string(),
                    valid_to: "2026-08-23T00:00:00".to_string(),
                    spent: false,
                },
                Credential {
                    unblinded: "token-two".to_string(),
                    valid_from: "2026-08-23T00:00:00".to_string(),
                    valid_to: "2026-08-24T00:00:00".to_string(),
                    spent: false,
                },
            ],
        }
    }

    #[test]
    fn a_batch_survives_a_round_trip_through_the_stored_form() {
        assert_eq!(decode(&encode(&batch())).unwrap(), batch());
    }

    /// Each channel keeps its own entry, so importing from Nightly must not overwrite Stable.
    #[test]
    fn each_channel_is_stored_separately() {
        let stable = format!("leo-premium-{}", crate::Channel::Stable.as_str());
        let nightly = format!("leo-premium-{}", crate::Channel::Nightly.as_str());
        assert_ne!(stable, nightly);
    }

    /// A credential is single-use, so the one presented must be valid *now*: a batch covers
    /// months of daily windows and most of it is not usable on any given day.
    #[test]
    fn the_next_usable_credential_is_the_one_valid_at_that_moment() {
        let batch = batch();
        assert_eq!(batch.next_usable("2026-08-22T12:00:00"), Some(0));
        assert_eq!(batch.next_usable("2026-08-23T12:00:00"), Some(1));
    }

    #[test]
    fn a_spent_credential_is_never_offered_again() {
        let mut batch = batch();
        batch.credentials[0].spent = true;
        assert_eq!(batch.next_usable("2026-08-22T12:00:00"), None);
        assert_eq!(batch.remaining(), 1);
    }

    /// Before the first window and after the last, there is nothing to present.
    #[test]
    fn a_moment_outside_every_window_yields_no_credential() {
        let batch = batch();
        assert_eq!(batch.next_usable("2026-08-21T23:59:59"), None);
        assert_eq!(batch.next_usable("2026-09-01T00:00:00"), None);
    }

    /// The end of a window is exclusive, so the credential that expires exactly now is not used.
    #[test]
    fn a_window_does_not_include_its_own_end() {
        let batch = batch();
        assert_eq!(batch.next_usable("2026-08-23T00:00:00"), Some(1));
    }

    #[test]
    fn a_batch_that_is_not_json_is_reported_as_malformed() {
        assert!(matches!(
            decode("not json").unwrap_err(),
            StoreError::Malformed { .. }
        ));
    }

    /// A credential with no token would fail at presentation time with something obscure, so it
    /// is rejected while there is still context to report.
    #[test]
    fn a_credential_without_a_token_is_rejected_on_load() {
        let raw = serde_json::json!({
            "version": 1,
            "order_id": "o", "item_id": "i", "issuer": "x",
            "credentials": [{ "valid_from": "a", "valid_to": "b", "spent": false }],
        })
        .to_string();
        assert!(matches!(
            decode(&raw).unwrap_err(),
            StoreError::Malformed { .. }
        ));
    }

    #[test]
    fn an_entry_missing_its_order_is_reported_as_malformed() {
        let raw = serde_json::json!({ "version": 1, "credentials": [] }).to_string();
        assert!(matches!(
            decode(&raw).unwrap_err(),
            StoreError::Malformed { .. }
        ));
    }
}
