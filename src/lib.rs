//! `svarog-eddsa`: Sparkle threshold EdDSA (Curve25519).
//!
//! * [`keygen`] - Feldman VSS + DLog proof + AES encrypted share distribution.
//! * [`sign_batch`] - Sparkle 3-round signing, N messages per batch.
//! * [`reshare`] - share rotation (player set and threshold unchanged).
//!
//! Messaging via [`curve_abstract::TrMessenger`]; errors via [`erreur::Resultat`].

#![allow(nonstandard_style)]

#[cfg(test)]
mod toy_messenger;
#[cfg(test)]
mod tests;

mod macros;

pub(crate) mod aes;
pub(crate) mod dlog_proof;
pub(crate) mod rng;

mod keygen;
pub use keygen::keygen;

mod sign;
pub use sign::{Signature, sign_batch};

mod reshare;
pub use reshare::reshare;

pub type Keystore = svarog_lagrange::Keystore<svarog_curve25519::Curve25519>;
