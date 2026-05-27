//! 端到端集成测试: keygen + sign_batch + reshare.

use std::collections::HashSet;
use std::sync::Arc;

use dashmap::DashMap;
use svarog_curve25519::Scalar;

use crate::toy_messenger::ToyMessenger;
use crate::{Keystore, Signature, keygen, reshare, sign_batch};

async fn run_keygen(players: HashSet<usize>, th: usize) -> Vec<Keystore> {
    let db = Arc::new(DashMap::new());
    let mut handles = Vec::new();
    for &i in &players {
        let dbi = db.clone();
        let pls = players.clone();
        let h = tokio::spawn(async move {
            let ch = ToyMessenger::new(dbi);
            keygen(ch, "dkg-sid".into(), pls, i, th, None, None)
                .await
                .unwrap()
        });
        handles.push(h);
    }
    let mut ks = Vec::with_capacity(players.len());
    for h in handles {
        ks.push(h.await.unwrap());
    }
    ks.sort_by_key(|k| k.i);
    ks
}

async fn run_sign(
    keystores: Vec<Keystore>,
    signers: HashSet<usize>,
    msgs: Vec<Vec<u8>>,
) -> Vec<Signature> {
    let db = Arc::new(DashMap::new());
    let sid = "sign-sid".to_string();
    let mut handles = Vec::new();
    for ks in keystores.into_iter().filter(|k| signers.contains(&k.i)) {
        let dbi = db.clone();
        let sg = signers.clone();
        let sid_i = sid.clone();
        let msgs_i = msgs.clone();
        let h = tokio::spawn(async move {
            let ch = ToyMessenger::new(dbi);
            // 全部 offset = 0, 等价于不做 BIP32 派生.
            let offsets: Vec<Scalar> = (0..msgs_i.len()).map(|_| Scalar::default()).collect();
            sign_batch(ch, sid_i, sg, &ks, offsets, msgs_i).await.unwrap()
        });
        handles.push(h);
    }
    let mut all = Vec::new();
    for h in handles {
        all.push(h.await.unwrap());
    }
    // 所有方应输出一致的签名向量.
    let first = all[0].clone();
    for sigs in &all[1..] {
        assert_eq!(sigs.len(), first.len());
        for (a, b) in sigs.iter().zip(first.iter()) {
            assert_eq!(a.R, b.R);
            assert_eq!(a.s, b.s);
        }
    }
    first
}

async fn run_reshare(
    sid: &str,
    inputs: Vec<(usize, Option<Keystore>)>,
    new_players: HashSet<usize>,
    th: usize,
) -> Vec<Keystore> {
    let db = Arc::new(DashMap::new());
    let mut handles = Vec::new();
    for (i, ks_opt) in inputs {
        let dbi = db.clone();
        let pls = new_players.clone();
        let sid_i = sid.to_string();
        let h = tokio::spawn(async move {
            let ch = ToyMessenger::new(dbi);
            reshare(ch, sid_i, pls, i, th, ks_opt.as_ref())
                .await
                .unwrap()
        });
        handles.push(h);
    }
    let mut ks = Vec::with_capacity(handles.len());
    for h in handles {
        ks.push(h.await.unwrap());
    }
    ks.sort_by_key(|k| k.i);
    ks
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn test_keygen_sign_2_of_2() {
    let players: HashSet<usize> = [1usize, 2].iter().copied().collect();
    let ks = run_keygen(players.clone(), 2).await;
    let sigs = run_sign(ks, players, vec![b"hello".to_vec()]).await;
    assert_eq!(sigs.len(), 1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn test_keygen_sign_2_of_3() {
    let players: HashSet<usize> = [1usize, 2, 3].iter().copied().collect();
    let ks = run_keygen(players.clone(), 2).await;
    let signers: HashSet<usize> = [1usize, 3].iter().copied().collect();
    let sigs = run_sign(ks, signers, vec![b"hello".to_vec()]).await;
    assert_eq!(sigs.len(), 1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn test_sign_batch_two_messages() {
    let players: HashSet<usize> = [1usize, 2].iter().copied().collect();
    let ks = run_keygen(players.clone(), 2).await;
    let sigs = run_sign(
        ks,
        players,
        vec![b"first message".to_vec(), b"second message".to_vec()],
    )
    .await;
    assert_eq!(sigs.len(), 2);
    assert_ne!(sigs[0].R, sigs[1].R);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn test_reshare_rotation_2_of_3() {
    let old_players: HashSet<usize> = [1usize, 2, 3].iter().copied().collect();
    let old_ks = run_keygen(old_players.clone(), 2).await;
    let pk = old_ks[0].public_key();
    let cc = old_ks[0].chain_code;
    let inputs: Vec<(usize, Option<Keystore>)> =
        old_ks.iter().map(|k| (k.i, Some(k.clone()))).collect();
    let new_ks = run_reshare("reshare-rot", inputs, old_players.clone(), 2).await;
    for k in &new_ks {
        assert_eq!(k.public_key(), pk);
        assert_eq!(k.chain_code, cc);
    }
    let signers: HashSet<usize> = [2usize, 3].iter().copied().collect();
    let _ = run_sign(new_ks, signers, vec![b"after rotation".to_vec()]).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn test_reshare_recover_lost_share() {
    let old_players: HashSet<usize> = [1usize, 2, 3].iter().copied().collect();
    let old_ks = run_keygen(old_players.clone(), 2).await;
    let pk = old_ks[0].public_key();
    let inputs: Vec<(usize, Option<Keystore>)> = old_ks
        .iter()
        .map(|k| (k.i, if k.i == 1 { None } else { Some(k.clone()) }))
        .collect();
    let new_ks = run_reshare("reshare-recover", inputs, old_players, 2).await;
    for k in &new_ks {
        assert_eq!(k.public_key(), pk);
    }
    // 含恢复方在内的任选两方签名.
    let signers: HashSet<usize> = [1usize, 2].iter().copied().collect();
    let _ = run_sign(new_ks, signers, vec![b"after recovery".to_vec()]).await;
}
