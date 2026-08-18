//! Threshold EdDSA MPC keygen (Curve25519).
//!
//! Stages:
//! 1. [FiX]      Broadcast Feldman commitments $F_i(X) = (g f_i)_0, \ldots, (g f_i)_{t-1}$.
//! 2. [xij_ct]   DH-AES encrypted share exchange $f_i(j)$. Verify via Feldman on receipt.
//! 3. [xi_proof] DLog proof for own final share $x_i$, mutually verified.
//!
//! Output: `svarog_lagrange::Keystore<Curve25519>`.

use std::collections::HashSet;

use curve_abstract::{TrCurve, TrMessenger, TrPoint as _, TrScalar as _};
use erreur::*;
use rug::{Integer, integer::Order};
use sha2::{Digest, Sha512};
use svarog_curve25519::Curve25519;
use svarog_lagrange::{Keystore, VerifiableSecretSharing};

use crate::aes::{aes_decrypt, aes_encrypt, AEAD};
use crate::dlog_proof::{DLogProof, dlog_prove, dlog_verify};
use crate::make_map;
use crate::rng::fill_random;

pub async fn keygen(
    mut chan: impl TrMessenger,
    sid: String,
    players: HashSet<usize>,
    i: usize,
    th: usize,
    imported_ui: Option<Integer>,
    chain_code: Option<[u8; 32]>,
) -> Resultat<Keystore<Curve25519>> {
    assert_throw!(
        players.contains(&i),
        "InvalidArgument",
        format!("keygen: party {} not in players", i)
    );

    let others = {
        let mut val = players.clone();
        let _ = val.remove(&i);
        val
    };

    // ===== [FiX] polynomial + commitments + broadcast =====
    let ui_original = match &imported_ui {
        None => {
            let mut num = [0u8; 32];
            fill_random(&mut num);
            Integer::from_digits(&num, Order::Msf)
        }
        Some(val) => val.clone(),
    };
    let ui = <Curve25519 as TrCurve>::ScalarT::new_from_int(&ui_original);
    let (_fiX, FiX, xij_send) = Curve25519::generate_shares(&ui, &players, th);

    let mut FjX_recv = make_map!(&players, Vec::<<Curve25519 as TrCurve>::PointT>::new());
    for j in &others {
        let FjX = FjX_recv.get_mut(j).unwrap();
        let _ = chan.register_send(&FiX, &sid, "FiX", i, *j, 0);
        let _ = chan.register_recv(FjX, &sid, "FiX", *j, i, 0);
    }
    chan.exchange()
        .await
        .catch("ExchangeFailed", "keygen stage: FiX")?;
    for j in &others {
        let FjX = &FjX_recv[j];
        // https://blog.trailofbits.com/2024/02/20/breaking-the-shared-key-in-threshold-signature-schemes/
        assert_throw!(
            FjX.len() == th,
            "InvalidPolyCommitLen",
            format!("keygen: peer {} sent FjX of wrong length", j)
        );
    }
    let _ = FjX_recv.insert(i, FiX);
    let vss_scheme = FjX_recv;

    let mut pk = Curve25519::identity().clone();
    for j in &players {
        let guj = &vss_scheme.get(j).unwrap()[0];
        pk = pk.add(guj);
    }
    let pk = pk;

    // ===== [xij_ct] DH-AES encrypted share exchange =====
    let mut aes_key_hold = make_map!(&others, Vec::<u8>::new());
    for j in &others {
        let guj = &vss_scheme.get(j).unwrap()[0];
        let dh = guj.mul_x(&ui).to_bytes();
        let _ = aes_key_hold.insert(*j, dh);
    }

    let mut xji_ct_recv_map = make_map!(&others, AEAD::default());
    for j in &others {
        let key = &aes_key_hold[j];
        let xij = xij_send[j].to_bytes();
        let xij_ct = aes_encrypt(key, &xij)
            .catch("AesEncryptFailed", format!("keygen: xij to peer {}", j))?;

        let xji = xji_ct_recv_map.get_mut(j).unwrap();
        let _ = chan.register_send(&xij_ct, &sid, "xij_ct", i, *j, 0);
        let _ = chan.register_recv(xji, &sid, "xij_ct", *j, i, 0);
    }
    chan.exchange()
        .await
        .catch("ExchangeFailed", "keygen stage: xij_ct")?;

    let mut xji_recv = make_map!(&others, Curve25519::zero().clone());
    let mut xi = xij_send[&i].clone();
    drop(xij_send);
    for j in &others {
        let key = &aes_key_hold[j];
        let xji_ct = &xji_ct_recv_map[j];
        let xji: Vec<u8> = aes_decrypt(key, xji_ct)
            .catch("AesDecryptFailed", format!("keygen: xji from peer {}", j))?;
        let xji = <Curve25519 as TrCurve>::ScalarT::new_from_bytes(&xji);
        let _ = xji_recv.insert(*j, xji);
    }
    Curve25519::verify_fj_at_i(i, &xji_recv, &vss_scheme)
        .catch("FeldmanVerifyFailed", "keygen: f_j(i) * G != F_j(i)")?;

    for j in &others {
        xi = xi.add(&xji_recv[j]);
    }
    drop(xji_ct_recv_map);

    // ===== [xi_proof] mutual DLog proof verification =====
    let (_, xi_proof) = dlog_prove::<Curve25519>(&xi);
    let mut xj_proof_recv = make_map!(&others, DLogProof::<Curve25519>::default());
    for j in &others {
        let xj_proof = xj_proof_recv.get_mut(j).unwrap();
        let _ = chan.register_send(&xi_proof, &sid, "xi_proof", i, *j, 0);
        let _ = chan.register_recv(xj_proof, &sid, "xi_proof", *j, i, 0);
    }
    chan.exchange()
        .await
        .catch("ExchangeFailed", "keygen stage: xi_proof")?;
    for j in &others {
        let xj_proof = &xj_proof_recv[j];
        let xjG = Curve25519::eval_xi_com(*j, &vss_scheme);
        dlog_verify(xj_proof, &xjG)
            .catch("InvalidDLogProof", format!("keygen: dishonest peer {}", j))?;
    }

    let chain_code = match chain_code {
        Some(val) => val,
        None => Sha512::digest(pk.to_bytes())[..32].try_into().unwrap(),
    };

    Ok(Keystore {
        i,
        ui: ui_original,
        xi,
        vss_scheme,
        chain_code,
        aux: vec![],
    })
}
