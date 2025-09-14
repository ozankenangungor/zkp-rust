use num_bigint::BigUint;

/// output = n^exp mod p
pub fn exponentiate(n: &BigUint, exponent: &BigUint, modulus: &BigUint) -> BigUint {
    n.modpow(exponent, modulus)
}

/// output = s = k - c * x mod q
pub fn solve(k: &BigUint, c: &BigUint, x: &BigUint, q: &BigUint) -> BigUint {
    let cx = c * x;

    if k >= &cx {
        (k - cx) % q
    } else {
        q - (cx - k) % q
    }
}

/// cond1: r1 = (alpha^s * y1^c) mod p
/// cond2: r2 = (beta^s * y2^c) mod p
pub fn verify(
    r1: &BigUint,
    r2: &BigUint,
    y1: &BigUint,
    y2: &BigUint,
    alpha: &BigUint,
    beta: &BigUint,
    c: &BigUint,
    s: &BigUint,
    p: &BigUint,
) -> bool {
    let term1_alpha = alpha.modpow(s, p);
    let term1_y = y1.modpow(c, p);
    let check1 = (term1_alpha * term1_y) % p;
    let cond1 = *r1 == check1;

    let term2_beta = beta.modpow(s, p);
    let term2_y = y2.modpow(c, p);
    let check2 = (term2_beta * term2_y) % p;
    let cond2 = *r2 == check2;

    cond1 && cond2
}
