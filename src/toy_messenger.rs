//! 测试用的内存 messenger. 实现 `TrMessenger` 接口, 通过共享 `DashMap`
//! 模拟多方异步收发. 仅用于单进程内的 tokio::spawn 测试, 非生产代码.
//!
//! 与 svarog-ecdsa-otmta 的 toy_messenger 同构, 可独立演进.

use std::{any::Any, collections::HashMap, sync::Arc};

use blake2::Blake2bVar;
use blake2::digest::{Update, VariableOutput};
use curve_abstract::TrMessenger;
use dashmap::DashMap;
use erreur::*;
use serde::{Deserialize, Serialize};
use tokio::time::{Duration, sleep};

type DePtr = *mut dyn Any;
type DeFn = Box<dyn Fn(&[u8], &mut dyn Any) -> Resultat<()>>;

pub struct ToyMessenger {
    db: Arc<DashMap<u128, Vec<u8>>>,
    tx: Vec<(u128, Vec<u8>)>,
    rx: HashMap<u128, (DePtr, DeFn)>,
}

unsafe impl Send for ToyMessenger {}

impl ToyMessenger {
    pub fn new(db: Arc<DashMap<u128, Vec<u8>>>) -> Self {
        Self {
            db,
            tx: Vec::new(),
            rx: HashMap::new(),
        }
    }
}

impl TrMessenger for ToyMessenger {
    type Err = Box<Erreur>;

    fn register_send<T>(
        &mut self,
        val: &T,
        sid: &str,
        topic: &str,
        src: usize,
        dst: usize,
        seq: usize,
    ) -> &mut Self
    where
        T: Serialize + for<'de> Deserialize<'de> + Clone + Send + Sync + 'static,
    {
        let key = index(sid, topic, src, dst, seq);
        let buf = serde_pickle::to_vec(val, Default::default()).unwrap();
        self.tx.push((key, buf));
        self
    }

    fn register_recv<T>(
        &mut self,
        out: &mut T,
        sid: &str,
        topic: &str,
        src: usize,
        dst: usize,
        seq: usize,
    ) -> &mut Self
    where
        T: Serialize + for<'de> Deserialize<'de> + Clone + Send + Sync + 'static,
    {
        let key = index(sid, topic, src, dst, seq);
        let de_ptr: DePtr = out as *mut T as *mut dyn Any;
        let de_fn: DeFn = Box::new(|bytes: &[u8], obj: &mut dyn Any| -> Resultat<()> {
            let obj_typed: &mut T = obj.downcast_mut().unwrap();
            *obj_typed = serde_pickle::from_slice(bytes, Default::default())
                .catch("DeserializationFailed", "ToyMessenger")?;
            Ok(())
        });
        let _ = self.rx.insert(key, (de_ptr, de_fn));
        self
    }

    async fn exchange(&mut self) -> Resultat<()> {
        for (key, val) in self.tx.drain(..) {
            let _ = self.db.insert(key, val);
        }
        let keys: Vec<u128> = self.rx.keys().cloned().collect();
        for key in &keys {
            while !self.db.contains_key(key) {
                sleep(Duration::from_millis(50)).await;
            }
            let buf = self.db.get(key).unwrap().clone();
            let (de_ptr, de_fn) = self.rx.get(key).unwrap();
            unsafe {
                de_fn(&buf, &mut **de_ptr)?;
            }
        }
        self.rx.clear();
        Ok(())
    }
}

fn index(sid: &str, topic: &str, src: usize, dst: usize, seq: usize) -> u128 {
    let mut hasher = Blake2bVar::new(16).unwrap();
    hasher.update(sid.as_bytes());
    hasher.update(b"|");
    hasher.update(topic.as_bytes());
    hasher.update(b"|");
    hasher.update(&src.to_le_bytes());
    hasher.update(&dst.to_le_bytes());
    hasher.update(&seq.to_le_bytes());
    let mut buf = [0u8; 16];
    hasher.finalize_variable(&mut buf).unwrap();
    u128::from_le_bytes(buf)
}
