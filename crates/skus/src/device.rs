//! Registering as an additional device on an existing subscription.
//!
//! The protocol is in the next commit. What is settled here is the shape of its result, because
//! [`crate::store`] persists it.

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
}

#[derive(Debug)]
pub enum DeviceError {
    /// The subscription is not in a state that can issue credentials.
    NotPaid,
    /// The server's signatures did not verify.
    ///
    /// Fatal on purpose: it means the batch was not signed by the key it claims, so nothing about
    /// it can be trusted.
    InvalidProof,
    /// The request did not complete.
    Transport { detail: String },
    /// The server answered with something unexpected.
    Unexpected { detail: String },
}

impl std::fmt::Display for DeviceError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotPaid => f.write_str("the subscription is not paid"),
            Self::InvalidProof => f.write_str("the credentials the server returned did not verify"),
            Self::Transport { detail } => {
                write!(f, "could not reach the subscription service: {detail}")
            }
            Self::Unexpected { detail } => write!(f, "unexpected response: {detail}"),
        }
    }
}

impl std::error::Error for DeviceError {}
