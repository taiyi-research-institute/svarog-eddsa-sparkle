//! `svarog-eddsa`: Sparkle 阈值 EdDSA (Curve25519) 实现.
//!
//! 公开 API 同 `svarog-ecdsa-otmta`, 方便业务层按算法选 crate:
//! * [`keygen`] - Feldman VSS + DLog 证明 + AES 加密的份额分发.
//! * [`sign_batch`] - Sparkle 3 轮签名, 一次跑 N 笔.
//! * [`reshare`] - 人数与门限不变的份额轮换.
//!
//! 消息层统一走 [`curve_abstract::TrMessenger`]; 错误统一为 [`erreur::Resultat`].

#![allow(nonstandard_style)]

#[cfg(test)]
mod toy_messenger;
#[cfg(test)]
mod tests;

mod keygen;
pub use keygen::keygen;

mod sign;
pub use sign::{Signature, sign_batch};

mod reshare;
pub use reshare::reshare;

/// 本 crate 公开的 `Keystore` 别名: 与 `vss::Keystore<Curve25519>` 同型.
pub type Keystore = vss::Keystore<svarog_curve25519::Curve25519>;

pub use vss::{int_to_mnemi, mnemi_to_int};

// ── anyhow → erreur 桥接 ────────────────────────────────────────────────
// vss / commons-mpc / bip32 等 common 依赖仍用 anyhow; 在本 crate 边界
// 用此 trait 翻成 Resultat.
//
// 由于 anyhow::Error 不直接 impl std::error::Error (官方有意为之, 防递归),
// 这里包一层 newtype 才能套上 erreur::Catch 的 trait bound.

use erreur::*;

#[derive(Debug)]
struct AnyhowErr(anyhow::Error);

impl std::fmt::Display for AnyhowErr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Display::fmt(&self.0, f)
    }
}
impl std::error::Error for AnyhowErr {}

pub(crate) trait AnyhowExt<T> {
    fn catch_anyhow(self, name: &str, ctx: impl AsRef<str>) -> Resultat<T>;
}

impl<T> AnyhowExt<T> for anyhow::Result<T> {
    #[track_caller]
    fn catch_anyhow(self, name: &str, ctx: impl AsRef<str>) -> Resultat<T> {
        self.map_err(AnyhowErr).catch(name, ctx)
    }
}
