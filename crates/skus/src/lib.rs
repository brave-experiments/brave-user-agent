//! Imports a Leo Premium subscription from a locally installed Brave Browser.
//!
//! # Why this crate has no labels
//!
//! Everything else that reaches the network in this repository carries a [`bua_core`] label and
//! passes a policy gate. This crate deliberately does neither, and the reason is that there is
//! nothing here for a gate to protect.
//!
//! A label answers "may this value influence what happens next", and the whole apparatus exists
//! because a turn mixes the user's instructions with bytes an attacker may have written. This
//! runs before any of that: a person types `bua import-leo-creds` at a shell, no planner exists,
//! no model has a context, and no untrusted document is in play. The subscription lives in the
//! user's own browser profile, the endpoint is a compiled-in constant, and the result goes into
//! the OS keychain. Nothing an attacker controls is anywhere in that path.
//!
//! So this is provisioning, not a turn. Do not wire it into [`bua_net::Egress`] or hand it a
//! `Policy`: that would add ceremony that protects nothing and would suggest, wrongly, that a
//! credential import is the kind of thing the information-flow rules were written about.
//!
//! What *does* apply is the rule in CLAUDE.md about not deciding from untrusted content, and it
//! is satisfied here for a stronger reason than a gate: the only value taken out of the browser
//! profile is an order id, which is checked against a UUID shape before it is used, and the only
//! value taken off the network is a credential batch that is verified cryptographically. Neither
//! is a decision an attacker can steer.
//!
//! # What is taken from the browser, and what is not
//!
//! Only the order id. Not the browser's credentials.
//!
//! That distinction is the point of the whole design. A subscription permits a limited number of
//! devices, so copying the stored credentials would spend the browser's own allocation and the
//! two installs would then fight over it. Instead this mints its own random tokens and has the
//! server sign them, which is exactly what a second browser on another machine does. See
//! [`device`] for the protocol.
//!
//! The profile is opened read-only and nothing is ever written back to it.

pub mod device;
pub mod profile;
pub mod store;

pub use device::{DeviceError, Registration};
pub use profile::{Channel, ProfileError, find_leo_order};
pub use store::{StoreError, StoredCredentials};

/// Where the credential endpoints live.
///
/// A constant rather than configuration: this is Brave's production payment service, the only
/// place a production subscription can be verified, and making it settable would turn a fixed
/// destination into one an environment could redirect.
pub const PAYMENT_BASE_URL: &str = "https://payment.rewards.brave.com";

/// The SKU a Leo Premium subscription is sold under.
pub const LEO_SKU: &str = "brave-leo-premium";

/// The order `location` that marks an order as Leo's.
///
/// A subscription to Brave VPN or Brave Search Premium sits in the same store, so the product is
/// identified by this rather than by being the only order present.
pub const LEO_LOCATION: &str = "leo.brave.com";

/// The cookie the aichat backend reads a subscription credential from.
pub const CREDENTIAL_COOKIE_NAME: &str = "__Secure-sku#brave-leo-premium";
