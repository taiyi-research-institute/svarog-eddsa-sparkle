//! 本仓库唯一的随机字节入口.

use rand::{TryRng, rngs::SysRng};

/// 用密码学安全的随机字节填满 `dst`.
///
/// 刻意用 `SysRng` 而不是 `rand::rng()`: 后者返回的 `ThreadRng` 是每线程缓存
/// 的 ChaCha12, 且**不在 `fork(2)` 时重新播种**, 子进程会逐字节重放父进程的
/// 字节流. 对本仓库而言, 这等于 DKG 秘密可预测 + AES-GCM 同钥重用 nonce.
///
/// `SysRng` 每次都走 `getrandom(2)`. 在 Linux 上该调用由 `__vdso_getrandom`
/// 在用户态服务 (常态不进内核), 且是 fork-safe 的.
///
/// OS RNG 失败时 panic 而非降级 — 与 `rand` 自身的失败语义一致.
pub(crate) fn fill_random(dst: &mut [u8]) {
    SysRng
        .try_fill_bytes(dst)
        .expect("OS random number generator failure");
}
