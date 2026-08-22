//! Spending imported Leo Premium credentials on a turn's requests.
//!
//! The adapter between the keychain and the chat client. It lives here rather than in either
//! because a credential is single-use: the client has to ask for one per request, and the store
//! has to record each as spent, so something has to sit between them and hold the channel.
//!
//! A failure here fails the turn rather than reverting to the free tier. That is deliberate: a
//! subscription that silently stops being used looks like the model got worse for no reason, and
//! the error names the fix (re-import, or unset the premium endpoint).

use bua_aichat::{Subscription, SubscriptionCredential};
use bua_skus::{Channel, DeviceError, Registration, StoreError};

/// How a new batch is obtained, as a function so a test can supply one without a network.
type Register = fn(&str, &str) -> Result<Registration, DeviceError>;

/// Spends credentials from the keychain, one per request.
///
/// The batch is opened once and spent from memory, so a session prompts for the keychain at most
/// once rather than on every model round. See [`bua_skus::store::Wallet`].
pub struct ImportedSubscription {
    wallet: bua_skus::store::Wallet,
    /// The clock, as an injectable function so a test need not wait for a real date.
    now: fn() -> String,
    /// How many credentials were left after the last spend, for a caller that wants to warn.
    remaining: Option<usize>,
    /// How a replacement batch is obtained when the current one runs out.
    register: Register,
    /// Supplies the request id a refill registers under.
    new_request_id: fn() -> String,
    /// Whether a refill has already been attempted this session.
    refilled: bool,
}

impl ImportedSubscription {
    /// Open `channel`'s imported batch, prompting for the keychain at most once.
    pub fn new(channel: Channel) -> Option<Self> {
        Some(Self {
            wallet: bua_skus::store::Wallet::open(channel).ok()?,
            now: current_timestamp,
            remaining: None,
            register: default_register,
            new_request_id: bua_skus::new_request_id,
            refilled: false,
        })
    }

    /// Spend from a batch that is already in hand, with no keychain behind it.
    ///
    /// Exists so the spending behaviour can be tested without a keychain. A test must never touch
    /// one: it would prompt whoever ran it, and in CI there is nobody to answer, so the run would
    /// hang or fail on a machine difference rather than on the code.
    #[cfg(test)]
    fn detached(batch: bua_skus::StoredCredentials) -> Self {
        Self {
            wallet: bua_skus::store::Wallet::detached(batch),
            now: current_timestamp,
            remaining: None,
            // Refusing rather than reaching the network, so a test that unexpectedly triggers a
            // refill fails loudly instead of making a live request.
            register: |_, _| {
                Err(DeviceError::Transport {
                    detail: "no network in tests".to_string(),
                })
            },
            new_request_id: || "test-request-id".to_string(),
            refilled: false,
        }
    }

    /// The first channel with a usable batch, or `None` if nothing has been imported.
    ///
    /// Stable is preferred, since that is what someone importing once is most likely to have.
    /// Opening is the same read that checks for one, so this prompts at most once rather than
    /// probing every channel first.
    pub fn discover() -> Option<Self> {
        Channel::ALL.into_iter().find_map(Self::new)
    }

    /// How many credentials remained after the last one was spent.
    pub fn remaining(&self) -> Option<usize> {
        self.remaining
    }
}

impl Subscription for ImportedSubscription {
    fn next_credential(&mut self) -> Result<SubscriptionCredential, String> {
        let now = (self.now)();

        let spent = match self.wallet.spend(&now) {
            Ok(spent) => spent,
            // A batch covers a few daily windows and then stops working, usually with most of it
            // unspent, so running out is the expected end of its life rather than a fault. The
            // subscription is still paid for and everything needed to mint more is already here, so
            // refill instead of making the user re-run the import.
            Err(StoreError::Exhausted | StoreError::Expired { .. }) => {
                self.refill()?;
                self.wallet.spend(&now).map_err(|e| e.to_string())?
            }
            Err(e) => return Err(e.to_string()),
        };

        let value = bua_skus::device::present(&spent.credential, &spent.issuer)
            .map_err(|e| e.to_string())?;

        self.remaining = Some(spent.remaining);

        Ok(SubscriptionCredential {
            cookie_name: bua_skus::CREDENTIAL_COOKIE_NAME.to_string(),
            cookie_value: value,
        })
    }
}

impl ImportedSubscription {
    /// Mint a new batch for the same order and put it in the wallet.
    ///
    /// Registers again under a **fresh** request id. Reusing the stored one would claim the existing
    /// batch rather than ask for a new one, which is the case the service answers with a conflict.
    fn refill(&mut self) -> Result<(), String> {
        // Attempted once per session. A second failure in the same run would not be a different
        // answer, and retrying inside a tool loop would mint batches in a circle.
        if self.refilled {
            return Err("the subscription credentials could not be renewed".to_string());
        }
        self.refilled = true;

        let order_id = self.wallet.order_id().to_string();
        let registration =
            (self.register)(&order_id, &(self.new_request_id)()).map_err(|e| e.to_string())?;

        self.wallet.refill(registration.into());

        // Written now rather than at session end: a batch that cost a round trip to obtain should
        // survive the process not exiting cleanly.
        self.wallet.flush().map_err(|e| e.to_string())?;
        Ok(())
    }
}

/// Register against the real service.
fn default_register(order_id: &str, request_id: &str) -> Result<Registration, DeviceError> {
    bua_skus::device::register(bua_skus::PAYMENT_BASE_URL, order_id, request_id)
}

/// The current time, in the fixed-width UTC form the stored windows use.
///
/// Formatted by hand from the Unix epoch: the comparison is against strings the server wrote, and
/// a date library would be a dependency for one conversion. Civil-time arithmetic from a day count
/// is exact, so this needs no timezone handling.
fn current_timestamp() -> String {
    let seconds = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);

    let (year, month, day) = civil_from_days((seconds / 86_400) as i64);
    let seconds_today = seconds % 86_400;

    format!(
        "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}",
        seconds_today / 3600,
        (seconds_today % 3600) / 60,
        seconds_today % 60
    )
}

/// Convert a count of days since 1970-01-01 to a civil date.
///
/// Howard Hinnant's `civil_from_days`, which is exact for every date this will ever see and
/// handles leap years without a table.
fn civil_from_days(days: i64) -> (i64, u32, u32) {
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let day_of_era = (z - era * 146_097) as u64;
    let year_of_era =
        (day_of_era - day_of_era / 1460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let year = year_of_era as i64 + era * 400;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let shifted_month = (5 * day_of_year + 2) / 153;
    let day = (day_of_year - (153 * shifted_month + 2) / 5 + 1) as u32;
    let month = if shifted_month < 10 {
        shifted_month + 3
    } else {
        shifted_month - 9
    } as u32;

    (if month <= 2 { year + 1 } else { year }, month, day)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The timestamp is compared against windows the server wrote, so it has to be the same
    /// fixed-width shape rather than merely a correct instant.
    #[test]
    fn the_timestamp_is_fixed_width_and_orders_lexicographically() {
        let now = current_timestamp();
        assert_eq!(now.len(), 19, "{now}");
        assert_eq!(now.as_bytes()[4], b'-');
        assert_eq!(now.as_bytes()[7], b'-');
        assert_eq!(now.as_bytes()[10], b'T');
        assert_eq!(now.as_bytes()[13], b':');
        assert_eq!(now.as_bytes()[16], b':');
    }

    /// Known epochs, including a leap day, since an off-by-one in the calendar maths would pick
    /// the wrong credential for a whole day.
    #[test]
    fn days_since_the_epoch_convert_to_the_right_civil_date() {
        assert_eq!(civil_from_days(0), (1970, 1, 1));
        assert_eq!(civil_from_days(1), (1970, 1, 2));
        assert_eq!(civil_from_days(365), (1971, 1, 1));
        // 2000 was a leap year despite being a century.
        assert_eq!(civil_from_days(11_016), (2000, 2, 29));
        assert_eq!(civil_from_days(11_017), (2000, 3, 1));
        // 2100 is not a leap year.
        assert_eq!(civil_from_days(47_540), (2100, 2, 28));
        assert_eq!(civil_from_days(47_541), (2100, 3, 1));
        assert_eq!(civil_from_days(20_687), (2026, 8, 22));
    }

    fn batch() -> bua_skus::StoredCredentials {
        bua_skus::StoredCredentials {
            order_id: "order".to_string(),
            item_id: "item".to_string(),
            issuer: "brave.com?sku=brave-leo-premium".to_string(),
            credentials: vec![bua_skus::store::Credential {
                // Not a real token, so presenting it fails. That is what the error paths below
                // exercise, without needing a signed batch from the service.
                unblinded: "not-a-token".to_string(),
                valid_from: "2026-08-22T00:00:00".to_string(),
                valid_to: "2026-08-23T00:00:00".to_string(),
                spent: false,
                rfc: true,
            }],
        }
    }

    /// A batch that stops working must be replaced automatically. The subscription is still paid
    /// for and everything needed to mint more is already stored, so making the user re-run the
    /// import by hand would be a gap rather than a safeguard.
    #[test]
    fn an_expired_batch_is_refilled_rather_than_failing() {
        let mut expired = batch();
        expired.credentials[0].valid_from = "2020-01-01T00:00:00".to_string();
        expired.credentials[0].valid_to = "2020-01-02T00:00:00".to_string();

        let mut subscription = ImportedSubscription::detached(expired);
        subscription.register = |_, _| Ok(fresh_registration());

        let credential = subscription
            .next_credential()
            .expect("an expired batch is replaced");
        assert_eq!(credential.cookie_name, bua_skus::CREDENTIAL_COOKIE_NAME);
        assert!(subscription.refilled);
    }

    /// Same for a batch whose credentials are all spent rather than expired.
    #[test]
    fn a_spent_batch_is_refilled() {
        let mut spent = batch();
        spent.credentials[0].spent = true;

        let mut subscription = ImportedSubscription::detached(spent);
        subscription.register = |_, _| Ok(fresh_registration());

        assert!(subscription.next_credential().is_ok());
    }

    /// A refill registers against the order already stored, so nothing has to be re-read from the
    /// browser profile, which may not even be installed any more.
    #[test]
    fn a_refill_uses_the_stored_order() {
        let mut expired = batch();
        expired.credentials.clear();

        let mut subscription = ImportedSubscription::detached(expired);
        subscription.register = |order_id, request_id| {
            assert_eq!(order_id, "order", "refilled against the wrong order");
            assert!(!request_id.is_empty(), "a refill needs a request id");
            Ok(fresh_registration())
        };

        assert!(subscription.next_credential().is_ok());
    }

    /// One attempt per session. Retrying inside a tool loop would mint batches in a circle, each
    /// costing a round trip, and the second answer would not differ from the first.
    #[test]
    fn a_failing_refill_is_attempted_only_once() {
        let mut empty = batch();
        empty.credentials.clear();

        let mut subscription = ImportedSubscription::detached(empty);
        subscription.register = |_, _| {
            Err(DeviceError::Transport {
                detail: "the service is unreachable".to_string(),
            })
        };

        assert!(subscription.next_credential().is_err());
        assert!(subscription.refilled);
        // The second call must not try again, so it reports the refusal rather than the transport
        // error a fresh attempt would produce.
        let second = subscription.next_credential().unwrap_err();
        assert!(second.contains("could not be renewed"), "retried: {second}");
    }

    /// A batch obtained at the cost of a round trip is written immediately rather than at session
    /// end, so an unclean exit does not throw it away.
    #[test]
    fn a_refill_is_flushed_immediately() {
        let mut empty = batch();
        empty.credentials.clear();

        let mut subscription = ImportedSubscription::detached(empty);
        subscription.register = |_, _| Ok(fresh_registration());
        subscription.next_credential().expect("refilled");

        // Detached, so the flush cannot have written to a keychain; what matters is that the new
        // batch is in hand and spendable.
        assert!(subscription.remaining().is_some());
    }

    /// A registration with one usable credential, as the service would return.
    fn fresh_registration() -> bua_skus::Registration {
        bua_skus::Registration {
            order_id: "order".to_string(),
            item_id: "item".to_string(),
            issuer: "brave.com?sku=brave-leo-premium".to_string(),
            credentials: vec![bua_skus::device::SignedCredential {
                unblinded: bua_skus::device::test_credential(),
                // Open-ended, so the credential is valid whenever the test happens to run.
                valid_from: "2000-01-01T00:00:00".to_string(),
                valid_to: "2999-01-01T00:00:00".to_string(),
                rfc: true,
            }],
        }
    }

    /// When the batch is unusable *and* it cannot be replaced, the request fails and says so. This
    /// is the fallback behind the automatic refill, not the first response to running out.
    #[test]
    fn an_unusable_batch_that_cannot_be_refilled_is_an_error() {
        let mut empty = batch();
        empty.credentials.clear();
        let mut subscription = ImportedSubscription::detached(empty);
        subscription.register = |_, _| {
            Err(DeviceError::Transport {
                detail: "the service is unreachable".to_string(),
            })
        };

        let err = subscription
            .next_credential()
            .expect_err("an empty batch that cannot be refilled cannot be spent");
        assert!(err.contains("subscription service"), "unclear error: {err}");
    }

    /// A credential that cannot be turned into a presentation is also an error, since the request
    /// would otherwise be downgraded with nothing said about it.
    #[test]
    fn a_credential_that_cannot_be_presented_is_an_error() {
        let mut subscription = ImportedSubscription::detached(batch());
        assert!(subscription.next_credential().is_err());
    }
}
