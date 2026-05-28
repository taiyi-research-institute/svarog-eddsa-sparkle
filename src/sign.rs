//! Sparkle threshold EdDSA batch signing (Curve25519).
//!
//! 3-round commit-reveal-respond, N messages per batch. For each (msg, tweak):
//! 1. Derive child public key $\mathrm{pk}^{(s)} = \mathrm{pk} + \nabla x^{(s)} G$, adjust $x_i^{(s)}$.
//! 2. R1 broadcast $H(m, S, R_i)$. R2 reveal $R_i$. R3 broadcast
//!    $z_i = r_i + c\cdot\lambda_i\cdot x_i^{(s)}$, where $c = H(R, \mathrm{pk}, m)$.
//! 3. Verify $z_j G = R_j + (\lambda_j c) X_j$, aggregate $s = \sum_i z_i$.
//!
//! Engineering hardening: $H(m, S, R_i)$ includes $(m, S)$ (not just $H(R_i)$ as in the paper),
//! preventing replay; the same $R_i$ commits differently across sessions/batches.

use std::collections::{HashMap, HashSet};

use curve_abstract::{TrMessenger, TrPoint as _, TrScalar as _};
use erreur::*;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha512, digest::Update};
use svarog_curve25519::{Curve25519, Point, Scalar};
use svarog_lagrange::{Keystore, VerifiableSecretSharing};

use crate::macros::make_vec_with;
use crate::{let_immutable, make_map, make_vec};

#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq, Eq)]
pub struct Signature {
    pub R: Point,
    pub s: Scalar,
}

pub async fn sign_batch(
    mut chan: impl TrMessenger,
    sid: String,
    signers: HashSet<usize>,
    keystore: &Keystore<Curve25519>,
    offsets: Vec<Scalar>,
    msgs: Vec<Vec<u8>>,
) -> Resultat<Vec<Signature>> {
    let base_pk = keystore.public_key();
    let sid = &sid;
    let my_id = keystore.i;
    assert_throw!(
        signers.contains(&my_id),
        "NotASigner",
        format!("sign_batch: party {} not in signers", my_id)
    );
    let others = {
        let mut val = signers.clone();
        let _ = val.remove(&my_id);
        val
    };
    let ntask = msgs.len();
    assert_throw!(ntask >= 1, "EmptyBatch", "sign_batch: msgs is empty");
    assert_throw!(
        offsets.len() == ntask,
        "LenMismatch",
        format!(
            "sign_batch: offsets.len()={} but msgs.len()={}",
            offsets.len(),
            ntask
        )
    );

    let mut S: Vec<usize> = signers.iter().cloned().collect();
    S.sort();
    let S: Vec<u8> = S.iter().flat_map(|&x| x.to_le_bytes()).collect();

    let recv_keys: HashSet<(usize, usize)> = {
        let mut obj = HashSet::new();
        for j in &others {
            for seq in 0..ntask {
                let _ = obj.insert((*j, seq));
            }
        }
        obj
    };

    // Non-hardened derivation (per-task tweak).
    let mut child_pk_vec = make_vec!(ntask, Point::default());
    let mut vss_scheme_vec = make_vec!(ntask, HashMap::<usize, Vec<Point>>::new());
    let mut xi_hold = make_vec!(ntask, Scalar::default());
    for seq in 0..ntask {
        let tweak_sk = offsets[seq].clone();
        let child_pk = base_pk.add_gx(&tweak_sk);
        let mut vss_scheme = keystore.vss_scheme.clone();
        let mut xi = keystore.xi.clone();
        xi = xi.add(&tweak_sk);

        let j = *vss_scheme.keys().min().unwrap();
        let guj = vss_scheme.get_mut(&j).unwrap().get_mut(0).unwrap();
        *guj = guj.add_gx(&tweak_sk);

        child_pk_vec[seq] = child_pk;
        vss_scheme_vec[seq] = vss_scheme;
        xi_hold[seq] = xi;
    }
    let_immutable!(child_pk_vec, vss_scheme_vec, xi_hold);

    // -- R1 broadcast $\mathrm{ComR}_i = H(m, S, R_i)$ --
    let ri_hold = make_vec_with(ntask, |_| Scalar::new_rand());
    let Ri_send = make_vec_with(ntask, |seq| Point::new_gx(&ri_hold[seq]));
    let ComRi_send = make_vec_with(ntask, |seq| {
        Sha512::new()
            .chain(&msgs[seq])
            .chain(&S)
            .chain(Ri_send[seq].to_bytes())
            .finalize()
            .to_vec()
    });
    let mut ComRj_recv = make_map!(&recv_keys, Vec::<u8>::new());

    for seq in 0..ntask {
        let val = &ComRi_send[seq];
        let _ = chan.register_send(val, sid, "ComRi", my_id, 0, seq);
        for j in &others {
            let out = ComRj_recv.get_mut(&(*j, seq)).unwrap();
            let _ = chan.register_recv(out, sid, "ComRi", *j, 0, seq);
        }
    }
    chan.exchange()
        .await
        .catch("ExchangeFailed", "sign_batch R1 (ComRi)")?;
    let_immutable!(ComRj_recv);

    // -- R2 reveal $R_i$ --
    let mut Rj_recv = make_map!(&recv_keys, Point::default());
    for seq in 0..ntask {
        let val = &Ri_send[seq];
        let _ = chan.register_send(val, sid, "Ri", my_id, 0, seq);
        for j in &others {
            let out = Rj_recv.get_mut(&(*j, seq)).unwrap();
            let _ = chan.register_recv(out, sid, "Ri", *j, 0, seq);
        }
    }
    chan.exchange()
        .await
        .catch("ExchangeFailed", "sign_batch R2 (Ri)")?;
    let_immutable!(Rj_recv);

    for seq in 0..ntask {
        for j in &others {
            let j_idx = &(*j, seq);
            let com_eval = Sha512::new()
                .chain(&msgs[seq])
                .chain(&S)
                .chain(Rj_recv[j_idx].to_bytes())
                .finalize()
                .to_vec();
            let com_recv = &ComRj_recv[j_idx];
            assert_throw!(
                &com_eval == com_recv,
                "InvalidCommitment",
                format!("sign_batch: ComR mismatch for peer {} seq {}", j, seq)
            );
        }
    }

    // Aggregate $R = \sum_j R_j$.
    let mut R_hold = make_vec!(ntask, Point::default());
    for seq in 0..ntask {
        let R = R_hold.get_mut(seq).unwrap();
        *R = R.add(&Ri_send[seq]);
        for j in &others {
            *R = R.add(&Rj_recv[&(*j, seq)]);
        }
    }
    let_immutable!(R_hold);

    // Challenge $c = H(R \| \mathrm{pk} \| m)$.
    let c_hold = make_vec_with(ntask, |seq| {
        let c = Sha512::new()
            .chain(R_hold[seq].to_bytes())
            .chain(child_pk_vec[seq].to_bytes())
            .chain(&msgs[seq])
            .finalize()
            .to_vec();
        Scalar::new_from_bytes(&c)
    });

    // -- R3 broadcast $z_i = r_i + c\cdot\lambda_i\cdot x_i$ --
    let lambda_i = Curve25519::lagrange_lambda(my_id, &signers);
    let zi_send = make_vec_with(ntask, |seq| {
        let c = &c_hold[seq];
        let ri = &ri_hold[seq];
        let xi = &xi_hold[seq];
        ri.add(&c.mul(&lambda_i).mul(xi))
    });
    let mut zj_recv = make_map!(&recv_keys, Scalar::default());
    for seq in 0..ntask {
        let val = &zi_send[seq];
        let _ = chan.register_send(val, sid, "zi", my_id, 0, seq);
        for j in &others {
            let out = zj_recv.get_mut(&(*j, seq)).unwrap();
            let _ = chan.register_recv(out, sid, "zi", *j, 0, seq);
        }
    }
    chan.exchange()
        .await
        .catch("ExchangeFailed", "sign_batch R3 (zi)")?;
    let_immutable!(zj_recv);

    // Verify $z_j G \stackrel{?}{=} R_j + (\lambda_j c) X_j$.
    for j in &others {
        let lambda_j = Curve25519::lagrange_lambda(*j, &signers);
        for seq in 0..ntask {
            let j_idx = &(*j, seq);
            let zjG = Point::new_gx(&zj_recv[j_idx]);
            let Rj = &Rj_recv[j_idx];
            let c = &c_hold[seq];
            let Xj = Curve25519::eval_xi_com(*j, &vss_scheme_vec[seq]);
            let zj_valid = zjG == Rj.add(&Xj.mul_x(&lambda_j.mul(c)));
            assert_throw!(
                zj_valid,
                "InvalidPartialSignature",
                format!("sign_batch: z_j check failed for peer {} seq {}", j, seq)
            );
        }
    }

    // Aggregate + local verify.
    let mut sig_vec = Vec::new();
    for seq in 0..ntask {
        let R = R_hold[seq].clone();
        let mut s = zi_send[seq].clone();
        for j in &others {
            let zj = &zj_recv[&(*j, seq)];
            s = s.add(zj);
        }
        let sig = Signature { R, s };
        sig.verify(&child_pk_vec[seq], &msgs[seq])
            .catch("EdDSAVerifyFailed", format!("sign_batch: seq {}", seq))?;
        sig_vec.push(sig);
    }

    Ok(sig_vec)
}

impl Signature {
    pub fn verify(&self, pk: &Point, m: &[u8]) -> Resultat<()> {
        let c = Sha512::new()
            .chain(self.R.to_bytes())
            .chain(pk.to_bytes())
            .chain(m)
            .finalize()
            .to_vec();
        let c = Scalar::new_from_bytes(&c);
        let lhs = Point::new_gx(&self.s);
        let rhs = self.R.add(&pk.mul_x(&c));
        assert_throw!(lhs == rhs, "EdDSAVerifyFailed", "EdDSA signature verification failed");
        Ok(())
    }

    pub fn to_rsv(&self) -> (Vec<u8>, Vec<u8>, u8) {
        (self.R.to_bytes(), self.s.to_bytes(), 0)
    }
}
