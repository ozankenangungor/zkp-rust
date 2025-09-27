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

#[cfg(test)]
mod tests {
    use super::*;
    use num_bigint::BigUint;

    #[test]
    fn test_schnorr_protocol_happy_path() {
        let alpha = BigUint::from(4u32);
        let beta = BigUint::from(9u32);
        let p = BigUint::from(23u32);
        let q = BigUint::from(11u32);

        let x = BigUint::from(6u32);
        let k = BigUint::from(7u32);

        let c = BigUint::from(4u32);

        let y1 = exponentiate(&alpha, &x, &p);
        let y2 = exponentiate(&beta, &x, &p);

        assert_eq!(y1, BigUint::from(2u32));
        assert_eq!(y2, BigUint::from(3u32));

        let r1 = exponentiate(&alpha, &k, &p);
        let r2 = exponentiate(&beta, &k, &p);

        assert_eq!(r1, BigUint::from(8u32));
        assert_eq!(r2, BigUint::from(4u32));

        let s = solve(&k, &c, &x, &q);

        assert_eq!(s, BigUint::from(5u32));

        let result = verify(&r1, &r2, &y1, &y2, &alpha, &beta, &c, &s, &p);

        assert!(
            result,
            "Validation should have been successful with correct inputs."
        );
    }

    #[test]
    fn test_schnorr_protocol_fake_secret_fails() {
        let alpha = BigUint::from(4u32);
        let beta = BigUint::from(9u32);
        let p = BigUint::from(23u32);
        let q = BigUint::from(11u32);

        let x = BigUint::from(6u32);
        let k = BigUint::from(7u32);
        let y1 = exponentiate(&alpha, &x, &p); // y1 = 2
        let y2 = exponentiate(&beta, &x, &p); // y2 = 3
        let r1 = exponentiate(&alpha, &k, &p); // r1 = 8
        let r2 = exponentiate(&beta, &k, &p); // r2 = 4

        let c = BigUint::from(4u32);

        let fake_secret = BigUint::from(7u32);

        let fake_s = solve(&k, &c, &fake_secret, &q);

        let fake_result = verify(&r1, &r2, &y1, &y2, &alpha, &beta, &c, &fake_s, &p);

        assert!(
            !fake_result,
            "The verification should have failed with a fake secret."
        );
    }
}
