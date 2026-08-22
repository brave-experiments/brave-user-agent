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
    /// Which key derivation this token was blinded with.
    ///
    /// Stored per credential because the two derivations yield different verification keys, and
    /// picking the wrong one produces a signature the server rejects with nothing to explain it.
    pub rfc: bool,
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
                    rfc: c.rfc,
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
///
/// Blocks for as long as the keychain takes, including while a password dialog waits to be
/// answered. There is no timeout: the answer to "may this read the credential" is the user's to
/// give, and abandoning the question would only turn it into a failure that looks like something
/// else. If this appears to hang, a dialog is waiting, possibly behind another window.
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

/// A batch held open for a session, spending from memory.
///
/// # Why this is not read per request
///
/// Reading the keychain prompts the user on macOS, and a credential is spent on *every* model
/// request, so touching the keychain per spend asks for a password several times per task. That is
/// worse than it sounds: prompts that often train a person to approve them without reading, which
/// costs more security than the per-use check was buying.
///
/// So the batch is read once, spent from memory, and the spent markers are written back when the
/// session ends or when [`Wallet::flush`] is called. The exposure is unchanged: a decrypted
/// credential was already in this process's memory the moment it was read.
///
/// The failure mode is losing spend markers if the process dies, which means a credential that was
/// presented is still recorded as unspent. That is deliberately the direction to fail in: a batch
/// is hundreds of credentials valid for days, so wasting a few is free, and the alternative
/// (recording a spend that never happened) is what runs the batch down for no benefit.
pub struct Wallet {
    batch: StoredCredentials,
    /// Where a flush writes to, or `None` for a detached batch that must never be written.
    ///
    /// Holding the destination rather than deciding at flush time is what makes a detached wallet
    /// safe: there is no channel to write to, so no code path, including [`Drop`], can reach the
    /// keychain. A boolean would leave a real destination sitting there for a later edit to use.
    destination: Option<crate::Channel>,
    /// Whether anything has been spent since the last write.
    dirty: bool,
}

impl Wallet {
    /// Read a channel's batch, prompting at most once.
    pub fn open(channel: crate::Channel) -> Result<Self, StoreError> {
        Ok(Self {
            batch: load(channel)?,
            destination: Some(channel),
            dirty: false,
        })
    }

    /// Hold a batch that is already in hand, with no keychain behind it.
    ///
    /// For tests, including those in crates above this one, which is why it is public. A test must
    /// never touch the real keychain: it would prompt whoever ran it, and in CI there is nobody to
    /// answer, so the run would fail on a machine difference rather than on the code.
    ///
    /// The result is detached, so spending and flushing behave normally but nothing is ever
    /// written, not even by [`Drop`].
    pub fn detached(batch: StoredCredentials) -> Self {
        Self {
            batch,
            destination: None,
            dirty: false,
        }
    }

    /// Take the next credential usable at `now`, marking it spent in memory.
    pub fn spend(&mut self, now: &str) -> Result<Spent, StoreError> {
        let index = self.batch.next_usable(now).ok_or(StoreError::Exhausted)?;
        self.batch.credentials[index].spent = true;
        self.dirty = true;

        Ok(Spent {
            credential: self.batch.credentials[index].clone(),
            issuer: self.batch.issuer.clone(),
            remaining: self.batch.remaining(),
        })
    }

    /// Write the spent markers back, if any.
    ///
    /// A no-op when nothing was spent, so an idle session never touches the keychain and never
    /// prompts, and a no-op for a detached batch, which has nowhere to write.
    pub fn flush(&mut self) -> Result<(), StoreError> {
        let Some(channel) = self.destination.filter(|_| self.dirty) else {
            return Ok(());
        };
        save(channel, &self.batch)?;
        self.dirty = false;
        Ok(())
    }

    pub fn remaining(&self) -> usize {
        self.batch.remaining()
    }
}

/// Writes the spent markers back, so a session that ends normally does not replay credentials.
///
/// Errors are dropped: this runs during teardown where there is nothing useful to do with one, and
/// the consequence is only that some spent credentials look unspent next time.
impl Drop for Wallet {
    fn drop(&mut self) {
        let _ = self.flush();
    }
}

/// A credential taken out of the store, already recorded as used.
#[derive(Debug, Clone)]
pub struct Spent {
    pub credential: Credential,
    /// The issuer string this credential's presentation signs over.
    pub issuer: String,
    /// How many are left, so a caller can warn before the batch runs out.
    pub remaining: usize,
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
                "rfc": c.rfc,
            }))
            .collect::<Vec<_>>(),
    })
    .to_string()
}

fn decode(raw: &str) -> Result<StoredCredentials, StoreError> {
    // An entry can exist holding nothing, if a write was interrupted partway. Reported as absent
    // rather than malformed, because the fix is the same as never having imported: run the import.
    if raw.trim().is_empty() {
        return Err(StoreError::NotFound);
    }

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
                // Every batch this writes is blinded with the rfc derivation, so that is the
                // reading for an entry that predates the field being recorded.
                rfc: c
                    .get("rfc")
                    .and_then(serde_json::Value::as_bool)
                    .unwrap_or(true),
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
                    rfc: true,
                },
                Credential {
                    unblinded: "token-two".to_string(),
                    valid_from: "2026-08-23T00:00:00".to_string(),
                    valid_to: "2026-08-24T00:00:00".to_string(),
                    spent: false,
                    rfc: true,
                },
            ],
        }
    }

    /// The reason Wallet exists: spending must not touch the keychain, because a credential is
    /// spent per model request and prompting that often is what drove the design.
    ///
    /// Asserted through the dirty flag, which is what decides whether a write happens at all.
    #[test]
    fn spending_does_not_write_until_asked_to() {
        let mut wallet = Wallet::detached(batch());
        assert!(!wallet.dirty, "a freshly opened batch has nothing to write");

        wallet
            .spend("2026-08-22T12:00:00")
            .expect("a usable credential");
        assert!(wallet.dirty, "a spend must be recorded for the next flush");
        assert_eq!(wallet.remaining(), 1);
    }

    /// A session that spends nothing must never write, so opening the agent and not using premium
    /// does not prompt for the keychain at all.
    #[test]
    fn a_session_that_spends_nothing_never_writes() {
        let mut wallet = Wallet::detached(batch());
        wallet.flush().expect("flushing nothing is a no-op");
        assert!(!wallet.dirty);
    }

    /// A detached batch must have no keychain destination at all, which is what lets these tests
    /// run in CI: there is nobody to answer a password prompt there, so a test that could reach the
    /// real keychain would hang or fail on a machine difference rather than on the code.
    #[test]
    fn a_detached_batch_has_nowhere_to_write() {
        let mut wallet = Wallet::detached(batch());
        assert!(wallet.destination.is_none());

        wallet
            .spend("2026-08-22T12:00:00")
            .expect("a usable credential");
        assert!(wallet.dirty, "the spend is recorded in memory");

        // Flushing a dirty detached batch is still a no-op, so neither this nor Drop can write.
        wallet.flush().expect("a detached flush cannot fail");
        assert!(wallet.dirty, "and it stays unwritten");
    }

    /// Two spends in one session must hand out different credentials: the whole batch is held in
    /// memory, so an index that did not advance would replay the same one every request.
    #[test]
    fn consecutive_spends_hand_out_different_credentials() {
        let mut batch = batch();
        // Both windows cover the same moment, so the only thing separating them is the spent mark.
        batch.credentials[1].valid_from = batch.credentials[0].valid_from.clone();
        batch.credentials[1].valid_to = batch.credentials[0].valid_to.clone();

        let mut wallet = Wallet::detached(batch);
        let first = wallet.spend("2026-08-22T12:00:00").expect("first");
        let second = wallet.spend("2026-08-22T12:00:00").expect("second");

        assert_ne!(first.credential.unblinded, second.credential.unblinded);
        assert_eq!(second.remaining, 0);
    }

    /// Once every credential in the window is spent, further requests must be refused rather than
    /// replaying one the server has already seen.
    #[test]
    fn spending_past_the_end_of_the_batch_is_refused() {
        let mut wallet = Wallet::detached(batch());
        wallet
            .spend("2026-08-22T12:00:00")
            .expect("the one usable credential");
        assert!(matches!(
            wallet.spend("2026-08-22T12:00:00"),
            Err(StoreError::Exhausted)
        ));
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

    /// An interrupted write can leave the entry present but empty. Reported as absent, since the
    /// remedy is the same as never having imported, and a JSON parse error here would send someone
    /// looking for corruption instead.
    #[test]
    fn an_empty_entry_is_reported_as_absent_rather_than_malformed() {
        assert!(matches!(decode("").unwrap_err(), StoreError::NotFound));
        assert!(matches!(decode("   ").unwrap_err(), StoreError::NotFound));
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
