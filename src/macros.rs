#[macro_export]
macro_rules! let_immutable {
    ($($var:ident),* $(,)?) => {
        $(let $var = $var;)*
    };
}

#[macro_export]
macro_rules! make_vec {
    ($length:expr, $fill:expr) => {{
        let mut obj: Vec<_> = Vec::new();
        let count = { $length };
        for _ in 0..count {
            let _ = obj.push({ $fill });
        }
        obj
    }};
}

pub fn make_vec_with<F, V>(count: usize, mut fill: F) -> Vec<V>
where
    F: FnMut(usize) -> V,
{
    let mut obj = Vec::with_capacity(count);
    for idx in 0..count {
        obj.push(fill(idx));
    }
    obj
}

#[macro_export]
macro_rules! make_map {
    ($keys:expr, $fill:expr) => {{
        let mut obj: std::collections::HashMap<_, _> = std::collections::HashMap::new();
        for key in { $keys }.iter().cloned() {
            let _ = obj.insert(key, { $fill });
        }
        obj
    }};
}
