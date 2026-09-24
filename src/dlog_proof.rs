use blake2::Blake2b512;
use curve_abstract::*;
use digest::Digest;
use erreur::*;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Default, Clone)]
pub struct DLogProof<C: TrCurve + Default + Clone + 'static> {
    pub rG: C::PointT,
    pub z: C::ScalarT,
}

pub fn dlog_prove<C>(w: &C::ScalarT) -> (C::PointT, DLogProof<C>)
where
    C: TrCurve + Default + Clone + 'static,
{
    let wG = C::PointT::new_gx(w);
    let r = C::ScalarT::new_rand();
    let rG = C::PointT::new_gx(&r);
    let c = Blake2b512::new()
        .chain_update(C::generator().to_bytes())
        .chain_update(rG.to_bytes())
        .chain_update(wG.to_bytes())
        .finalize();
    let c = C::ScalarT::new_from_bytes(&c);
    let z = c.mul(w).add(&r);

    (wG, DLogProof { rG, z })
}

pub fn dlog_verify<C>(proof: &DLogProof<C>, S: &C::PointT) -> Resultat<()>
where
    C: TrCurve + Default + Clone + 'static,
{
    let c = Blake2b512::new()
        .chain_update(C::generator().to_bytes())
        .chain_update(proof.rG.to_bytes())
        .chain_update(S.to_bytes())
        .finalize();
    let c = C::ScalarT::new_from_bytes(&c);

    let rhs = C::PointT::new_gx(&proof.z).sub(&S.mul_x(&c));
    assert_throw!(
        proof.rG == rhs,
        "InvalidDLogProof",
        "DLog verification failed"
    );
    Ok(())
}
