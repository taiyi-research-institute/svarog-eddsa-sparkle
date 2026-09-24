//! Threshold EdDSA share rotation (reshare). Player set and threshold unchanged.
//!
//! Protocol shape matches [`svarog_ecdsa_otmta::reshare`]:
//! * Round 0a (broadcast) alive announcement. Active producers also broadcast
//!   `expected_pk` and `chain_code` (from their `Keystore`).
//! * Round 0b (P2P) active producers randomly split $\lambda_i x_i$ into
//!   $N$ additive shares, sending the $k$-th share to party $k$.
//! * Then delegate to [`crate::keygen`] with `imported_ui = sum of received splits`,
//!   preserving `chain_code`. Finally compare aggregated pk against consensus PK.
//!
//! Lost-share set is implicit: whoever does not claim `has_share` in Round 0a is lost.

use std::collections::{HashMap, HashSet};

use curve_abstract::{TrCurve, TrMessenger, TrScalar as _};
use erreur::*;
use serde::{Deserialize, Serialize};
use svarog_curve25519::{Curve25519, Point, Scalar};
use svarog_lagrange::{Keystore, VerifiableSecretSharing};

use crate::keygen;

#[derive(Clone, Default, Serialize, Deserialize)]
struct AliveAnnounce {
    has_share: bool,
    pk_and_cc: Option<(Point, [u8; 32])>,
}

pub async fn reshare(
    mut chan: impl TrMessenger,
    sid: String,
    new_players: HashSet<usize>,
    i: usize,
    th: usize,
    old_keystore: Option<&Keystore<Curve25519>>,
) -> Resultat<Keystore<Curve25519>> {
    assert_throw!(
        new_players.contains(&i),
        "InvalidArgument",
        format!("reshare: party {} not in new_players", i)
    );

    if let Some(ks) = old_keystore {
        let old_set: HashSet<usize> = ks.vss_scheme.keys().copied().collect();
        assert_throw!(
            old_set == new_players,
            "InvalidArgument",
            "reshare: keystore's old player set must match new_players"
        );
    }

    let others: Vec<usize> = {
        let mut v: Vec<usize> = new_players.iter().copied().filter(|&p| p != i).collect();
        v.sort();
        v
    };
    let new_player_ordered: Vec<usize> = {
        let mut v: Vec<usize> = new_players.iter().copied().collect();
        v.sort();
        v
    };

    // -- Round 0a: alive announcement + (expected_pk, chain_code) broadcast --
    let my_announce = match old_keystore {
        Some(ks) => AliveAnnounce {
            has_share: true,
            pk_and_cc: Some((ks.public_key(), ks.chain_code)),
        },
        None => AliveAnnounce::default(),
    };

    let mut announces: HashMap<usize, AliveAnnounce> = HashMap::new();
    let _ = announces.insert(i, my_announce.clone());
    for &j in &others {
        let _ = announces.insert(j, AliveAnnounce::default());
    }
    let _ = chan.register_send(&my_announce, &sid, "reshare/r0a/announce", i, 0, 0);
    for &j in &others {
        let slot = announces.get_mut(&j).unwrap();
        let _ = chan.register_recv(slot, &sid, "reshare/r0a/announce", j, 0, 0);
    }
    chan.exchange()
        .await
        .catch("ExchangeFailed", "reshare Round 0a")?;

    let active_producers: HashSet<usize> = announces
        .iter()
        .filter_map(|(&id, a)| if a.has_share { Some(id) } else { None })
        .collect();

    assert_throw!(
        active_producers.len() >= th,
        "InsufficientActiveProducers",
        format!(
            "reshare: need >= {} active producers, got {}",
            th,
            active_producers.len()
        )
    );

    let mut consensus: Option<(Point, [u8; 32])> = None;
    for &p in &active_producers {
        let pkc = announces[&p].pk_and_cc.as_ref().ifnone(
            "MalformedReshareAnnounce",
            format!(
                "reshare: producer {} announced has_share=true but no pk/cc",
                p
            ),
        )?;
        match &consensus {
            Some(c) => assert_throw!(
                c == pkc,
                "InconsistentReshareAnnounce",
                format!(
                    "reshare: producer {} disagrees with peers on pk/chain_code",
                    p
                )
            ),
            None => consensus = Some(pkc.clone()),
        }
    }
    let (expected_pk, chain_code) = consensus.unwrap();

    // -- Round 0b: producer random split + P2P --
    let mut received_splits: HashMap<usize, Scalar> = HashMap::new();
    let mut my_pieces: HashMap<usize, Scalar> = HashMap::new();

    if let Some(ks) = old_keystore {
        let lambda_i = Curve25519::lagrange_lambda(i, &active_producers);
        let xi_scalar = Scalar::new_from_int(ks.xi.to_int());
        let s_i = lambda_i.mul(&xi_scalar);

        let mut running = s_i.clone();
        for (idx, &k) in new_player_ordered.iter().enumerate() {
            if idx + 1 < new_player_ordered.len() {
                let r = Scalar::new_rand();
                running = running.sub(&r);
                let _ = my_pieces.insert(k, r);
            } else {
                let _ = my_pieces.insert(k, running.clone());
            }
        }

        let _ = received_splits.insert(i, my_pieces[&i].clone());
        for &j in &others {
            let _ = chan.register_send(&my_pieces[&j], &sid, "reshare/r0b/split", i, j, 0);
        }
    }

    for &p in &active_producers {
        if p == i {
            continue;
        }
        let _ = received_splits.insert(p, Scalar::default());
    }
    for &p in &active_producers {
        if p == i {
            continue;
        }
        let slot = received_splits.get_mut(&p).unwrap();
        let _ = chan.register_recv(slot, &sid, "reshare/r0b/split", p, i, 0);
    }
    chan.exchange()
        .await
        .catch("ExchangeFailed", "reshare Round 0b")?;

    let mut ui_scalar = Curve25519::zero().clone();
    for s in received_splits.values() {
        ui_scalar = ui_scalar.add(s);
    }
    let imported_ui = Some(ui_scalar.to_int());

    // -- Reuse keygen with forced constant term + chain code --
    let ks = keygen(chan, sid, new_players, i, th, imported_ui, Some(chain_code)).await?;

    assert_throw!(
        ks.public_key() == expected_pk,
        "InvalidKeyRefresh",
        "reshare: aggregated public key does not match expected"
    );

    Ok(ks)
}
