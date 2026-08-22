//! Registering as an additional device on an existing subscription.
//!
//! # Why this is not taking the browser's credentials
//!
//! A subscription permits several devices, and each one holds credentials of its own. So the way
//! to add this agent is the way a second browser on another machine does it: generate random
//! tokens locally, have the server blind-sign them, and keep the result. The browser's own
//! credentials are never read and never spent, and its device slot is untouched.
//!
//! Nothing but the order id is needed to start. The server answers with the item id and how many
//! credentials the subscription allows, which is also more current than the copy in the profile
//! after a renewal.
//!
//! # The protocol
//!
//! Brave's SKU service issues privacy-preserving credentials, so a credential cannot be linked
//! back to the subscription that paid for it. That shapes every step:
//!
//! 1. Generate `num_intervals * num_per_interval` random tokens.
//! 2. Blind them, which hides the tokens from the server that signs them.
//! 3. `PUT` the blinded tokens under a fresh request id. The request id is what makes this a
//!    *new* device rather than a competing claim on an existing batch.
//! 4. `GET` the signed tokens back, with a batch DLEQ proof.
//! 5. Verify that proof and unblind. This is the step that matters: it proves the server signed
//!    the tokens with the key it published, so a tampered or substituted batch is rejected rather
//!    than stored.
//!
//! Verification failure is fatal and deliberately not recoverable. A batch that does not verify
//! was not signed by the advertised key, so nothing about it can be relied on.
//!
//! # Presenting one
//!
//! A credential is single-use. Presenting it derives a verification key from the unblinded token,
//! signs the issuer string with it, and sends the result; the server recognises the signature
//! without learning which subscription it came from. The derivation has two forms and the wrong
//! one produces a signature that simply fails, so which was used is recorded per credential.

use challenge_bypass_ristretto::voprf::{
    BatchDLEQProof, BlindedToken, PublicKey, SignedToken, Token, UnblindedToken,
};
use hmac::Hmac;
use rand::rngs::OsRng;
use sha2::Sha512;

type HmacSha512 = Hmac<Sha512>;

/// How long to wait for the credential service.
const TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

/// How many times to poll for a batch the server is still signing.
///
/// Signing is asynchronous: the service answers `202` until the batch is ready.
const MAX_POLLS: usize = 10;

/// How long to wait between polls.
const POLL_INTERVAL: std::time::Duration = std::time::Duration::from_secs(2);

/// A cap on the batch size, so a malformed order cannot ask this to mint unbounded tokens.
///
/// A Leo subscription is 3 intervals of 192, so this leaves generous headroom while still being a
/// bound. Each token costs a scalar multiplication, so an absurd count would otherwise be a way
/// to make this spin.
const MAX_CREDENTIALS: usize = 10_000;

/// The outcome of registering: a batch of credentials this install owns.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Registration {
    pub order_id: String,
    pub item_id: String,
    /// The `merchant?sku=` string a presentation signs over.
    pub issuer: String,
    pub credentials: Vec<SignedCredential>,
}

/// One credential as the server signed it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedCredential {
    /// Base64 unblinded token.
    pub unblinded: String,
    pub valid_from: String,
    pub valid_to: String,
    /// Which key derivation this token was blinded with.
    ///
    /// Recorded because the two derivations produce different verification keys and the wrong one
    /// yields a signature the server rejects without saying why.
    pub rfc: bool,
}

#[derive(Debug)]
pub enum DeviceError {
    /// The subscription is not in a state that can issue credentials.
    NotPaid { status: String },
    /// The order exists but has no Leo item to issue credentials for.
    NoItem,
    /// The order does not say how many credentials it allows.
    ///
    /// Only time-limited-v2 orders carry the interval metadata this needs.
    NoMetadata,
    /// The server's signatures did not verify.
    ///
    /// Fatal on purpose: it means the batch was not signed by the key it claims, so nothing about
    /// it can be trusted.
    InvalidProof,
    /// The server was still signing after the last poll.
    StillSigning,
    /// The request did not complete.
    Transport { detail: String },
    /// The server answered with something unexpected.
    Unexpected { detail: String },
}

impl std::fmt::Display for DeviceError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotPaid { status } => {
                write!(f, "the subscription is '{status}', not paid")
            }
            Self::NoItem => f.write_str("the order contains no Leo Premium item"),
            Self::NoMetadata => {
                f.write_str("the order does not say how many credentials it allows")
            }
            Self::InvalidProof => f.write_str("the credentials the server returned did not verify"),
            Self::StillSigning => f.write_str(
                "the subscription service is still preparing the credentials; try again shortly",
            ),
            Self::Transport { detail } => {
                write!(f, "could not reach the subscription service: {detail}")
            }
            Self::Unexpected { detail } => write!(f, "unexpected response: {detail}"),
        }
    }
}

impl std::error::Error for DeviceError {}

/// What the order says about the credentials it can issue.
#[derive(Debug, Clone, PartialEq, Eq)]
struct OrderDetails {
    item_id: String,
    merchant_id: String,
    sku: String,
    /// How many credentials the whole subscription period covers.
    total_credentials: usize,
}

/// Register this install as another device on `order_id`.
///
/// `request_id` identifies this batch. A fresh uuid means a new device; reusing one would claim an
/// existing device's batch, which is why the caller supplies it explicitly rather than having one
/// generated somewhere less visible.
pub fn register(
    base_url: &str,
    order_id: &str,
    request_id: &str,
) -> Result<Registration, DeviceError> {
    let agent = ureq::Agent::config_builder()
        .timeout_global(Some(TIMEOUT))
        .build();
    let agent: ureq::Agent = agent.into();

    let details = fetch_order(&agent, base_url, order_id)?;

    // Held so the signed tokens can be unblinded against the tokens that produced them. The
    // server never sees these.
    let tokens: Vec<Token> = (0..details.total_credentials)
        .map(|_| Token::random::<Sha512, _>(&mut OsRng))
        .collect();

    let blinded: Vec<BlindedToken> = tokens
        .iter()
        .map(|t| t.blind_rfc::<Sha512>())
        .collect::<Result<_, _>>()
        .map_err(|e| DeviceError::Unexpected {
            detail: format!("could not blind the tokens: {e}"),
        })?;

    submit_batch(
        &agent,
        base_url,
        order_id,
        &details.item_id,
        request_id,
        &blinded,
    )?;

    let batches = collect_batch(&agent, base_url, order_id, &details.item_id, request_id)?;

    let issuer = format!("{}?sku={}", details.merchant_id, details.sku);
    let mut credentials = Vec::new();

    for batch in batches {
        // The server states which blinded tokens it signed, and they are matched back to the
        // tokens held here rather than assumed to be in the same order. A token the server did not
        // sign is skipped, and one it invented matches nothing.
        let mut mine: Vec<(usize, &Token)> = Vec::new();
        let mut signed_for_mine: Vec<SignedToken> = Vec::new();
        let mut blinded_for_mine: Vec<BlindedToken> = Vec::new();

        for (position, returned) in batch.blinded.iter().enumerate() {
            let encoded = returned.encode_base64();
            if let Some(index) = blinded
                .iter()
                .position(|b| b.encode_base64() == encoded)
                .filter(|index| !mine.iter().any(|(taken, _)| taken == index))
            {
                let Some(signed) = batch.signed.get(position) else {
                    continue;
                };
                mine.push((index, &tokens[index]));
                blinded_for_mine.push(*returned);
                signed_for_mine.push(*signed);
            }
        }

        if mine.is_empty() {
            continue;
        }

        // The gate on the whole exchange: this fails unless the batch was signed by the key the
        // server published, over exactly these tokens.
        let unblinded: Vec<UnblindedToken> = batch
            .proof
            .verify_and_unblind::<Sha512, _>(
                mine.iter().map(|(_, token)| *token),
                &blinded_for_mine,
                &signed_for_mine,
                &batch.public_key,
            )
            .map_err(|_| DeviceError::InvalidProof)?;

        for token in unblinded {
            credentials.push(SignedCredential {
                unblinded: token.encode_base64(),
                valid_from: batch.valid_from.clone(),
                valid_to: batch.valid_to.clone(),
                // Every token here was blinded with blind_rfc, so the matching derivation is the
                // rfc one.
                rfc: true,
            });
        }
    }

    if credentials.is_empty() {
        return Err(DeviceError::Unexpected {
            detail: "the server signed none of the tokens submitted".to_string(),
        });
    }

    Ok(Registration {
        order_id: order_id.to_string(),
        item_id: details.item_id,
        issuer,
        credentials,
    })
}

/// The cookie value that presents `credential`.
///
/// Base64 of the redemption document the backend expects. Spending is the caller's job: this
/// derives the presentation and does not mark anything used.
pub fn present(credential: &crate::store::Credential, issuer: &str) -> Result<String, DeviceError> {
    let token = UnblindedToken::decode_base64(&credential.unblinded).map_err(|e| {
        DeviceError::Unexpected {
            detail: format!("stored credential is not a token: {e}"),
        }
    })?;

    // The two derivations yield different keys, and the wrong one produces a signature the server
    // rejects with nothing to explain it.
    let verification_key = if credential.rfc {
        token.derive_verification_key_rfc::<Sha512>()
    } else {
        token.derive_verification_key::<Sha512>()
    };

    let signature = verification_key
        .sign::<HmacSha512>(issuer.as_bytes())
        .encode_base64();

    let redemption = serde_json::json!({
        "validFrom": credential.valid_from,
        "validTo": credential.valid_to,
        "issuer": issuer,
        "t": token.t.encode_base64(),
        "signature": signature,
    });

    // The cookie is not the redemption document, it is a request *about* one, with the redemption
    // carried inside as its own base64 string. Sending the inner document alone is the natural
    // mistake and the server rejects it as an invalid credential without saying why.
    //
    // `version` is 2 because that is what a time-limited-v2 credential is verified as; the type
    // name and the version are separate fields and both are checked.
    let request = serde_json::json!({
        "type": "time-limited-v2",
        "version": 2,
        "sku": crate::LEO_SKU,
        "presentation": base64_encode(redemption.to_string().as_bytes()),
    });

    // Base64 only. brave-core url-encodes at this point, but it is building a `Set-Cookie` value
    // for a browser to store; this is a `Cookie` request header, and a percent-encoded payload is
    // rejected as a malformed credential.
    Ok(base64_encode(request.to_string().as_bytes()))
}

/// Read the order, and with it what credentials may be issued.
fn fetch_order(
    agent: &ureq::Agent,
    base_url: &str,
    order_id: &str,
) -> Result<OrderDetails, DeviceError> {
    let url = format!("{base_url}/v1/orders/{order_id}");
    let body = get_text(agent, &url)?;
    parse_order(&body)
}

/// Pull the credential-issuing details out of an order response.
///
/// Split from the request so the shape can be tested without a server.
fn parse_order(body: &str) -> Result<OrderDetails, DeviceError> {
    let order: serde_json::Value =
        serde_json::from_str(body).map_err(|e| DeviceError::Unexpected {
            detail: format!("the order was not JSON: {e}"),
        })?;

    let status = order
        .get("status")
        .and_then(serde_json::Value::as_str)
        .unwrap_or_default();
    if status != "paid" {
        return Err(DeviceError::NotPaid {
            status: status.to_string(),
        });
    }

    let merchant_id = order
        .get("merchantId")
        .or_else(|| order.get("merchant_id"))
        .and_then(serde_json::Value::as_str)
        .unwrap_or("brave.com")
        .to_string();

    // The Leo item, not merely the first: an order may carry more than one line.
    let item = order
        .get("items")
        .and_then(serde_json::Value::as_array)
        .and_then(|items| {
            items
                .iter()
                .find(|item| {
                    item.get("sku").and_then(serde_json::Value::as_str) == Some(crate::LEO_SKU)
                })
                .or_else(|| items.first())
        })
        .ok_or(DeviceError::NoItem)?;

    let item_id = item
        .get("id")
        .and_then(serde_json::Value::as_str)
        .ok_or(DeviceError::NoItem)?
        .to_string();

    let sku = item
        .get("sku")
        .and_then(serde_json::Value::as_str)
        .unwrap_or(crate::LEO_SKU)
        .to_string();

    let metadata = order.get("metadata").ok_or(DeviceError::NoMetadata)?;
    let number = |name: &str, alternative: &str| {
        metadata
            .get(name)
            .or_else(|| metadata.get(alternative))
            .and_then(serde_json::Value::as_u64)
    };
    let intervals = number("numIntervals", "num_intervals").ok_or(DeviceError::NoMetadata)?;
    let per_interval =
        number("numPerInterval", "num_per_interval").ok_or(DeviceError::NoMetadata)?;

    let total = (intervals as usize)
        .checked_mul(per_interval as usize)
        .filter(|total| *total > 0 && *total <= MAX_CREDENTIALS)
        .ok_or_else(|| DeviceError::Unexpected {
            detail: format!(
                "the order asks for an implausible {intervals}x{per_interval} credentials"
            ),
        })?;

    Ok(OrderDetails {
        item_id,
        merchant_id,
        sku,
        total_credentials: total,
    })
}

/// Offer the blinded tokens for signing.
fn submit_batch(
    agent: &ureq::Agent,
    base_url: &str,
    order_id: &str,
    item_id: &str,
    request_id: &str,
    blinded: &[BlindedToken],
) -> Result<(), DeviceError> {
    let url = batch_url(base_url, order_id, item_id, request_id);
    let body = serde_json::json!({
        "blindedCreds": blinded.iter().map(|b| b.encode_base64()).collect::<Vec<_>>(),
    })
    .to_string();

    match agent.put(&url).content_type("application/json").send(&body) {
        Ok(_) => Ok(()),
        // The batch is already on file under this request id. Harmless: the tokens were sent
        // before and the next step reads them back.
        Err(ureq::Error::StatusCode(409)) => Ok(()),
        Err(ureq::Error::StatusCode(code)) => Err(status_error(code)),
        Err(e) => Err(DeviceError::Transport {
            detail: e.to_string(),
        }),
    }
}

/// A batch of signed tokens, as returned for one validity window.
#[derive(Debug)]
struct SignedBatch {
    blinded: Vec<BlindedToken>,
    signed: Vec<SignedToken>,
    proof: BatchDLEQProof,
    public_key: PublicKey,
    valid_from: String,
    valid_to: String,
}

/// Collect the signed tokens, waiting while the server is still working.
fn collect_batch(
    agent: &ureq::Agent,
    base_url: &str,
    order_id: &str,
    item_id: &str,
    request_id: &str,
) -> Result<Vec<SignedBatch>, DeviceError> {
    let url = batch_url(base_url, order_id, item_id, request_id);

    for attempt in 0..MAX_POLLS {
        match agent.get(&url).call() {
            Ok(mut response) => {
                // 202 means the batch is accepted but not signed yet, and it carries an empty
                // list. Checked on the success path because that is where it arrives: only 4xx
                // and 5xx surface as errors, so treating this as a response to parse would read
                // "not ready" as "nothing was signed".
                let still_signing = response.status() == 202;

                let body =
                    response
                        .body_mut()
                        .read_to_string()
                        .map_err(|e| DeviceError::Transport {
                            detail: e.to_string(),
                        })?;

                if !still_signing {
                    return parse_batches(&body);
                }

                if attempt + 1 == MAX_POLLS {
                    return Err(DeviceError::StillSigning);
                }
                std::thread::sleep(POLL_INTERVAL);
            }
            Err(ureq::Error::StatusCode(code)) => return Err(status_error(code)),
            Err(e) => {
                return Err(DeviceError::Transport {
                    detail: e.to_string(),
                });
            }
        }
    }

    Err(DeviceError::StillSigning)
}

/// Decode the signed batches from a response body.
fn parse_batches(body: &str) -> Result<Vec<SignedBatch>, DeviceError> {
    let value: serde_json::Value =
        serde_json::from_str(body).map_err(|e| DeviceError::Unexpected {
            detail: format!("the credentials were not JSON: {e}"),
        })?;

    // A single object and a list of them are both possible, since one request may cover several
    // validity windows.
    let entries = match value {
        serde_json::Value::Array(entries) => entries,
        object => vec![object],
    };

    let mut batches = Vec::new();

    for entry in entries {
        let strings = |name: &str| -> Vec<String> {
            entry
                .get(name)
                .and_then(serde_json::Value::as_array)
                .map(|values| {
                    values
                        .iter()
                        .filter_map(serde_json::Value::as_str)
                        .map(str::to_string)
                        .collect()
                })
                .unwrap_or_default()
        };

        let text = |name: &str, alternative: &str| {
            entry
                .get(name)
                .or_else(|| entry.get(alternative))
                .and_then(serde_json::Value::as_str)
                .unwrap_or_default()
                .to_string()
        };

        let blinded: Vec<BlindedToken> = strings("blindedCreds")
            .iter()
            .filter_map(|s| BlindedToken::decode_base64(s).ok())
            .collect();
        let signed: Vec<SignedToken> = strings("signedCreds")
            .iter()
            .filter_map(|s| SignedToken::decode_base64(s).ok())
            .collect();

        // A window with nothing signed yet is not an error, just nothing to take.
        if blinded.is_empty() || signed.is_empty() {
            continue;
        }

        let proof = entry
            .get("batchProof")
            .and_then(serde_json::Value::as_str)
            .and_then(|s| BatchDLEQProof::decode_base64(s).ok())
            .ok_or(DeviceError::InvalidProof)?;

        let public_key = entry
            .get("publicKey")
            .and_then(serde_json::Value::as_str)
            .and_then(|s| PublicKey::decode_base64(s).ok())
            .ok_or(DeviceError::InvalidProof)?;

        batches.push(SignedBatch {
            blinded,
            signed,
            proof,
            public_key,
            valid_from: naive_timestamp(&text("validFrom", "valid_from")),
            valid_to: naive_timestamp(&text("validTo", "valid_to")),
        });
    }

    if batches.is_empty() {
        return Err(DeviceError::Unexpected {
            detail: "the server returned no signed credentials".to_string(),
        });
    }

    Ok(batches)
}

/// Drop the zone marker the credential service puts on a validity timestamp.
///
/// The service sends `...Z`, but a presentation must not carry it: brave-core parses these into a
/// zone-less local type and re-serialises them without one, and the presented document has to match
/// what the verifying end expects. Passing the string through verbatim looks harmless and produces a
/// document that differs from every other client's by one character.
///
/// Only the marker goes. These are already UTC, so nothing is being converted.
fn naive_timestamp(value: &str) -> String {
    value.trim_end_matches('Z').to_string()
}

fn batch_url(base_url: &str, order_id: &str, item_id: &str, request_id: &str) -> String {
    format!("{base_url}/v1/orders/{order_id}/credentials/items/{item_id}/batches/{request_id}")
}

fn status_error(code: u16) -> DeviceError {
    match code {
        404 => DeviceError::Unexpected {
            detail: "the subscription service does not know this order".to_string(),
        },
        401 | 403 => DeviceError::Unexpected {
            detail: "the subscription service refused the request".to_string(),
        },
        other => DeviceError::Unexpected {
            detail: format!("the subscription service answered {other}"),
        },
    }
}

/// Read a URL as text.
fn get_text(agent: &ureq::Agent, url: &str) -> Result<String, DeviceError> {
    match agent.get(url).call() {
        Ok(mut response) => {
            response
                .body_mut()
                .read_to_string()
                .map_err(|e| DeviceError::Transport {
                    detail: e.to_string(),
                })
        }
        Err(ureq::Error::StatusCode(code)) => Err(status_error(code)),
        Err(e) => Err(DeviceError::Transport {
            detail: e.to_string(),
        }),
    }
}

/// Standard base64, written out to avoid a dependency for one encoding.
fn base64_encode(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);

    for chunk in bytes.chunks(3) {
        let b = [
            chunk[0],
            chunk.get(1).copied().unwrap_or(0),
            chunk.get(2).copied().unwrap_or(0),
        ];
        let triple = (u32::from(b[0]) << 16) | (u32::from(b[1]) << 8) | u32::from(b[2]);
        for shift in [18, 12, 6, 0] {
            out.push(ALPHABET[(triple >> shift) as usize & 0x3f] as char);
        }
        // Pad out the characters the missing input bytes would have produced.
        let padding = 3 - chunk.len();
        out.truncate(out.len() - padding);
        out.push_str(&"=".repeat(padding));
    }

    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use challenge_bypass_ristretto::voprf::SigningKey;

    fn order_json(status: &str, intervals: u64, per_interval: u64) -> String {
        serde_json::json!({
            "id": "3cc63766-991f-4c87-984e-ecdea77c86d8",
            "status": status,
            "location": "leo.brave.com",
            "merchantId": "brave.com",
            "items": [{
                "id": "b7114ccc-b3a5-4951-9a5d-8b7a28731111",
                "sku": "brave-leo-premium",
                "credentialType": "time-limited-v2"
            }],
            "metadata": { "numIntervals": intervals, "numPerInterval": per_interval }
        })
        .to_string()
    }

    #[test]
    fn an_order_says_how_many_credentials_to_ask_for() {
        let details = parse_order(&order_json("paid", 3, 192)).unwrap();
        assert_eq!(details.item_id, "b7114ccc-b3a5-4951-9a5d-8b7a28731111");
        assert_eq!(details.total_credentials, 3 * 192);
    }

    /// The batch size comes from the server, so a nonsensical count must be refused rather than
    /// turned into that many scalar multiplications.
    #[test]
    fn an_implausible_credential_count_is_refused() {
        let err = parse_order(&order_json("paid", 1_000_000, 1_000_000)).unwrap_err();
        assert!(matches!(err, DeviceError::Unexpected { .. }));
    }

    #[test]
    fn an_order_asking_for_no_credentials_is_refused() {
        let err = parse_order(&order_json("paid", 0, 192)).unwrap_err();
        assert!(matches!(err, DeviceError::Unexpected { .. }));
    }

    #[test]
    fn an_unpaid_order_cannot_be_registered_against() {
        let err = parse_order(&order_json("canceled", 3, 192)).unwrap_err();
        assert!(matches!(err, DeviceError::NotPaid { .. }));
    }

    /// Only time-limited-v2 orders carry interval metadata, and without it there is no way to know
    /// how many credentials to mint.
    #[test]
    fn an_order_without_interval_metadata_is_refused() {
        let body = serde_json::json!({
            "status": "paid",
            "items": [{ "id": "i", "sku": "brave-leo-premium" }]
        })
        .to_string();
        assert!(matches!(
            parse_order(&body).unwrap_err(),
            DeviceError::NoMetadata
        ));
    }

    /// An order may hold more than one line, so the Leo item has to be picked rather than the
    /// first one taken.
    #[test]
    fn the_leo_item_is_picked_out_of_a_multi_item_order() {
        let body = serde_json::json!({
            "status": "paid",
            "merchantId": "brave.com",
            "items": [
                { "id": "other-item", "sku": "brave-vpn-premium" },
                { "id": "leo-item", "sku": "brave-leo-premium" }
            ],
            "metadata": { "numIntervals": 3, "numPerInterval": 192 }
        })
        .to_string();
        assert_eq!(parse_order(&body).unwrap().item_id, "leo-item");
    }

    /// The issuer string is what a presentation signs over, so it must match what the server
    /// derives from the order.
    #[test]
    fn the_issuer_combines_the_merchant_and_the_sku() {
        let details = parse_order(&order_json("paid", 3, 192)).unwrap();
        assert_eq!(
            format!("{}?sku={}", details.merchant_id, details.sku),
            "brave.com?sku=brave-leo-premium"
        );
    }

    /// Sign a batch the way the service does, so the verifying path can be exercised without one.
    fn sign_batch(blinded: &[BlindedToken]) -> (Vec<SignedToken>, BatchDLEQProof, PublicKey) {
        let key = SigningKey::random(&mut OsRng);
        let signed: Vec<SignedToken> = blinded.iter().map(|b| key.sign(b).unwrap()).collect();
        let proof = BatchDLEQProof::new::<Sha512, _>(&mut OsRng, blinded, &signed, &key).unwrap();
        (signed, proof, key.public_key)
    }

    /// Mint one credential the way a real exchange would, through proof verification.
    ///
    /// Unblinding on its own is not reachable from outside the crate, which is the right shape:
    /// a credential only exists once the batch it came in has been verified.
    fn issue_one_credential() -> UnblindedToken {
        let token = Token::random::<Sha512, _>(&mut OsRng);
        let blinded = token.blind_rfc::<Sha512>().unwrap();
        let blinded = [blinded];
        let (signed, proof, public_key) = sign_batch(&blinded);
        proof
            .verify_and_unblind::<Sha512, _>(
                std::iter::once(&token),
                &blinded,
                &signed,
                &public_key,
            )
            .unwrap()
            .remove(0)
    }

    fn batch_body(
        blinded: &[BlindedToken],
        signed: &[SignedToken],
        proof: &BatchDLEQProof,
        public_key: &PublicKey,
    ) -> String {
        serde_json::json!([{
            "blindedCreds": blinded.iter().map(|b| b.encode_base64()).collect::<Vec<_>>(),
            "signedCreds": signed.iter().map(|s| s.encode_base64()).collect::<Vec<_>>(),
            "batchProof": proof.encode_base64(),
            "publicKey": public_key.encode_base64(),
            "validFrom": "2026-08-22T00:00:00Z",
            "validTo": "2026-08-23T00:00:00Z",
        }])
        .to_string()
    }

    #[test]
    fn a_well_formed_batch_is_decoded() {
        let tokens: Vec<Token> = (0..4)
            .map(|_| Token::random::<Sha512, _>(&mut OsRng))
            .collect();
        let blinded: Vec<BlindedToken> = tokens
            .iter()
            .map(|t| t.blind_rfc::<Sha512>().unwrap())
            .collect();
        let (signed, proof, public_key) = sign_batch(&blinded);

        let batches = parse_batches(&batch_body(&blinded, &signed, &proof, &public_key)).unwrap();
        assert_eq!(batches.len(), 1);
        assert_eq!(batches[0].signed.len(), 4);
        // Stored without the zone marker, which is the form a presentation must carry.
        assert_eq!(batches[0].valid_to, "2026-08-23T00:00:00");
    }

    /// The proof is the whole point of the exchange: a batch signed by some other key must be
    /// rejected, not stored.
    #[test]
    fn a_batch_signed_by_the_wrong_key_does_not_verify() {
        let tokens: Vec<Token> = (0..4)
            .map(|_| Token::random::<Sha512, _>(&mut OsRng))
            .collect();
        let blinded: Vec<BlindedToken> = tokens
            .iter()
            .map(|t| t.blind_rfc::<Sha512>().unwrap())
            .collect();
        let (signed, proof, _) = sign_batch(&blinded);
        // A different key's public half, as a substituted or tampered response would carry.
        let (_, _, other_public_key) = sign_batch(&blinded);

        let verified = proof.verify_and_unblind::<Sha512, _>(
            tokens.iter(),
            &blinded,
            &signed,
            &other_public_key,
        );
        assert!(verified.is_err(), "a foreign key must not verify");
    }

    /// Tokens are matched back by their blinded form rather than by position, so a reordered
    /// response still yields the right credentials.
    #[test]
    fn tokens_are_matched_by_value_not_by_position() {
        let tokens: Vec<Token> = (0..3)
            .map(|_| Token::random::<Sha512, _>(&mut OsRng))
            .collect();
        let blinded: Vec<BlindedToken> = tokens
            .iter()
            .map(|t| t.blind_rfc::<Sha512>().unwrap())
            .collect();
        let encoded: Vec<String> = blinded.iter().map(|b| b.encode_base64()).collect();

        let mut reversed = blinded.clone();
        reversed.reverse();
        let reencoded: Vec<String> = reversed.iter().map(|b| b.encode_base64()).collect();

        assert_eq!(reencoded[0], encoded[2]);
        assert_ne!(reencoded[0], encoded[0]);
    }

    #[test]
    fn a_response_with_no_signed_credentials_is_an_error() {
        let body = serde_json::json!([{ "blindedCreds": [], "signedCreds": [] }]).to_string();
        assert!(matches!(
            parse_batches(&body).unwrap_err(),
            DeviceError::Unexpected { .. }
        ));
    }

    /// A batch with credentials but no proof cannot be verified, so it must be refused rather
    /// than accepted unverified.
    #[test]
    fn a_batch_without_a_proof_is_refused() {
        let tokens: Vec<Token> = (0..2)
            .map(|_| Token::random::<Sha512, _>(&mut OsRng))
            .collect();
        let blinded: Vec<BlindedToken> = tokens
            .iter()
            .map(|t| t.blind_rfc::<Sha512>().unwrap())
            .collect();
        let (signed, _, public_key) = sign_batch(&blinded);

        let body = serde_json::json!([{
            "blindedCreds": blinded.iter().map(|b| b.encode_base64()).collect::<Vec<_>>(),
            "signedCreds": signed.iter().map(|s| s.encode_base64()).collect::<Vec<_>>(),
            "publicKey": public_key.encode_base64(),
        }])
        .to_string();

        assert!(matches!(
            parse_batches(&body).unwrap_err(),
            DeviceError::InvalidProof
        ));
    }

    /// The request path is built from the order and item ids, so it must be the documented shape.
    /// The service sends `...Z` but a presentation must not carry it, because brave-core round-trips
    /// these through a zone-less type and the verifying end expects that form. One stray character
    /// is the difference between a valid presentation and a rejected one.
    #[test]
    fn the_zone_marker_is_dropped_from_validity_timestamps() {
        assert_eq!(
            naive_timestamp("2026-08-22T20:18:06Z"),
            "2026-08-22T20:18:06"
        );
        // Already zone-less, so unchanged rather than truncated.
        assert_eq!(
            naive_timestamp("2026-08-22T20:18:06"),
            "2026-08-22T20:18:06"
        );
        assert_eq!(naive_timestamp(""), "");
    }

    /// The decoded batch must already hold the presentable form, so nothing downstream has to
    /// remember to strip it.
    #[test]
    fn a_decoded_batch_holds_presentable_timestamps() {
        let tokens: Vec<Token> = (0..2)
            .map(|_| Token::random::<Sha512, _>(&mut OsRng))
            .collect();
        let blinded: Vec<BlindedToken> = tokens
            .iter()
            .map(|t| t.blind_rfc::<Sha512>().unwrap())
            .collect();
        let (signed, proof, public_key) = sign_batch(&blinded);

        let batches = parse_batches(&batch_body(&blinded, &signed, &proof, &public_key)).unwrap();
        assert_eq!(batches[0].valid_to, "2026-08-23T00:00:00");
        assert!(!batches[0].valid_from.ends_with('Z'));
    }

    #[test]
    fn the_batch_url_addresses_the_orders_item() {
        assert_eq!(
            batch_url("https://payment.example", "order-1", "item-2", "request-3"),
            "https://payment.example/v1/orders/order-1/credentials/items/item-2/batches/request-3"
        );
    }

    /// A presentation must be base64 of a redemption document, since that is what the backend
    /// decodes out of the cookie.
    #[test]
    fn a_presentation_carries_the_signed_redemption() {
        let unblinded = issue_one_credential();

        let credential = crate::store::Credential {
            unblinded: unblinded.encode_base64(),
            valid_from: "2026-08-22T00:00:00Z".to_string(),
            valid_to: "2026-08-23T00:00:00Z".to_string(),
            spent: false,
            rfc: true,
        };

        let presentation = present(&credential, "brave.com?sku=brave-leo-premium").unwrap();
        let outer: serde_json::Value =
            serde_json::from_slice(&decode_base64_for_test(&presentation)).unwrap();

        // The outer layer describes what is being presented. Sending the redemption without it is
        // what the service reports as an invalid credential, with nothing to say which part is
        // wrong.
        assert_eq!(outer["type"], "time-limited-v2");
        assert_eq!(outer["version"], 2);
        assert_eq!(outer["sku"], "brave-leo-premium");

        // The redemption is nested inside, as its own base64 string.
        let inner = outer["presentation"].as_str().expect("a nested redemption");
        let document: serde_json::Value =
            serde_json::from_slice(&decode_base64_for_test(inner)).unwrap();

        assert_eq!(document["issuer"], "brave.com?sku=brave-leo-premium");
        assert_eq!(document["validTo"], "2026-08-23T00:00:00Z");
        assert!(
            document["signature"]
                .as_str()
                .is_some_and(|s| !s.is_empty())
        );
        assert!(document["t"].as_str().is_some_and(|s| !s.is_empty()));
    }

    /// The cookie must be plain base64. brave-core percent-encodes at the equivalent point, but it
    /// is building a Set-Cookie value for a browser to store; a percent-encoded payload in a Cookie
    /// request header is rejected as a malformed credential.
    #[test]
    fn the_presentation_is_base64_and_not_percent_encoded() {
        let credential = crate::store::Credential {
            unblinded: issue_one_credential().encode_base64(),
            valid_from: "2026-08-22T00:00:00".to_string(),
            valid_to: "2026-08-23T00:00:00".to_string(),
            spent: false,
            rfc: true,
        };

        let presentation = present(&credential, "brave.com?sku=brave-leo-premium").unwrap();
        assert!(
            !presentation.contains('%'),
            "percent-encoded: {presentation}"
        );
        // Base64 of a JSON object always begins with the encoding of '{'.
        assert!(
            presentation.starts_with('e'),
            "not base64 JSON: {presentation}"
        );
    }

    /// The rfc flag selects the key derivation, and the wrong one yields a different signature
    /// that the server would reject without explanation.
    #[test]
    fn the_derivation_flag_changes_the_signature() {
        let unblinded = issue_one_credential();

        let mut credential = crate::store::Credential {
            unblinded: unblinded.encode_base64(),
            valid_from: "a".to_string(),
            valid_to: "b".to_string(),
            spent: false,
            rfc: true,
        };
        let with_rfc = present(&credential, "issuer").unwrap();
        credential.rfc = false;
        let without_rfc = present(&credential, "issuer").unwrap();

        assert_ne!(with_rfc, without_rfc);
    }

    #[test]
    fn base64_matches_known_encodings() {
        assert_eq!(base64_encode(b""), "");
        assert_eq!(base64_encode(b"f"), "Zg==");
        assert_eq!(base64_encode(b"fo"), "Zm8=");
        assert_eq!(base64_encode(b"foo"), "Zm9v");
        assert_eq!(base64_encode(b"foob"), "Zm9vYg==");
        assert_eq!(base64_encode(b"fooba"), "Zm9vYmE=");
        assert_eq!(base64_encode(b"foobar"), "Zm9vYmFy");
    }

    fn decode_base64_for_test(text: &str) -> Vec<u8> {
        const ALPHABET: &[u8; 64] =
            b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let mut bits = Vec::new();
        for byte in text.bytes().filter(|b| *b != b'=') {
            let value = ALPHABET.iter().position(|c| *c == byte).unwrap() as u32;
            bits.push(value);
        }
        let mut out = Vec::new();
        for chunk in bits.chunks(4) {
            let mut packed = 0u32;
            for (index, value) in chunk.iter().enumerate() {
                packed |= value << (18 - 6 * index);
            }
            let produced = chunk.len() - 1;
            for index in 0..produced {
                out.push((packed >> (16 - 8 * index)) as u8);
            }
        }
        out
    }
}
