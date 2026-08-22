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
use bua_skus::Channel;

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
}

impl ImportedSubscription {
    /// Open `channel`'s imported batch, prompting for the keychain at most once.
    pub fn new(channel: Channel) -> Option<Self> {
        Some(Self {
            wallet: bua_skus::store::Wallet::open(channel).ok()?,
            now: current_timestamp,
            remaining: None,
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
        }
    }

    /// The first channel with a usable batch, or `None` if nothing has been imported.
    ///
    /// Stable is preferred, since that is what someone importing once is most likely to have.
    /// Opening is the same read that checks for one, so this prompts at most once rather than
    /// probing every channel first.
    pub fn discover() -> Option<Self> {
        [Channel::Stable, Channel::Beta, Channel::Nightly]
            .into_iter()
            .find_map(Self::new)
    }

    /// How many credentials remained after the last one was spent.
    pub fn remaining(&self) -> Option<usize> {
        self.remaining
    }
}

impl Subscription for ImportedSubscription {
    fn next_credential(&mut self) -> Result<SubscriptionCredential, String> {
        let spent = self
            .wallet
            .spend(&(self.now)())
            .map_err(|e| e.to_string())?;

        let value = bua_skus::device::present(&spent.credential, &spent.issuer)
            .map_err(|e| e.to_string())?;

        self.remaining = Some(spent.remaining);

        Ok(SubscriptionCredential {
            cookie_name: bua_skus::CREDENTIAL_COOKIE_NAME.to_string(),
            cookie_value: value,
        })
    }
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

    /// An empty batch must report an error, not hand back nothing and let the request quietly go
    /// out on the free tier.
    #[test]
    fn a_batch_with_nothing_usable_is_an_error() {
        let mut empty = batch();
        empty.credentials.clear();
        let mut subscription = ImportedSubscription::detached(empty);

        let err = subscription
            .next_credential()
            .expect_err("an empty batch cannot be spent");
        assert!(err.contains("used up"), "unhelpful message: {err}");
    }

    /// A credential that cannot be turned into a presentation is also an error, since the request
    /// would otherwise be downgraded with nothing said about it.
    #[test]
    fn a_credential_that_cannot_be_presented_is_an_error() {
        let mut subscription = ImportedSubscription::detached(batch());
        assert!(subscription.next_credential().is_err());
    }

    /// The error has to name what to do about it: a bare failure mid-task leaves nothing to act on.
    #[test]
    fn the_exhausted_error_says_how_to_fix_it() {
        let mut empty = batch();
        empty.credentials.clear();
        let mut subscription = ImportedSubscription::detached(empty);

        let err = subscription.next_credential().unwrap_err();
        assert!(err.contains("import-leo-creds"), "no remedy offered: {err}");
    }
}
