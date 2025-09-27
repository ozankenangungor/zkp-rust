use num_bigint::{BigUint, RandBigInt};
use rand::thread_rng;

/// output = n^exp mod p
pub fn exponentiate(n: &BigUint, exponent: &BigUint, modulus: &BigUint) -> BigUint {
    n.modpow(exponent, modulus)
}

/// Less than a given upper bound ('bound'), cryptographically
/// secure random BigUint number.
pub fn generate_random_below(bound: &BigUint) -> BigUint {
    let mut rng = thread_rng();
    rng.gen_biguint_below(bound)
}

// --- MAIN PROTOCOL STRUCTURE ---

/// Structure that holds the fixed, global parameters of the Schnorr protocol together.
pub struct SchnorrProtocol {
    pub p: BigUint,
    pub q: BigUint,
    pub alpha: BigUint,
    pub beta: BigUint,
}

impl SchnorrProtocol {
    pub fn new(p: BigUint, q: BigUint, alpha: BigUint, beta: BigUint) -> Self {
        Self { p, q, alpha, beta }
    }

    /// output = s = k - c * x mod q
    pub fn solve(&self, k: &BigUint, c: &BigUint, x: &BigUint) -> BigUint {
        let cx = c * x;
        let q = &self.q;

        if k >= &cx {
            (k - cx) % q
        } else {
            q - (cx - k) % q
        }
    }

    /// cond1: r1 = (alpha^s * y1^c) mod p
    /// cond2: r2 = (beta^s * y2^c) mod p
    pub fn verify(
        &self,
        r1: &BigUint,
        r2: &BigUint,
        y1: &BigUint,
        y2: &BigUint,
        c: &BigUint,
        s: &BigUint,
    ) -> bool {
        let p = &self.p;
        let alpha = &self.alpha;
        let beta = &self.beta;

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
}

#[cfg(test)]
mod tests {
    use super::*;
    use num_bigint::BigUint;

    #[test]
    fn test_schnorr_protocol_with_random_values() {
        let p = BigUint::from(23u32);
        let q = BigUint::from(11u32);
        let alpha = BigUint::from(4u32);
        let beta = BigUint::from(9u32);

        let protocol = SchnorrProtocol::new(p.clone(), q.clone(), alpha.clone(), beta.clone());

        let x = BigUint::from(6u32);
        let y1 = exponentiate(&alpha, &x, &p);
        let y2 = exponentiate(&beta, &x, &p);

        let k = generate_random_below(&q);
        let c = generate_random_below(&q);

        let r1 = exponentiate(&alpha, &k, &p);
        let r2 = exponentiate(&beta, &k, &p);
        let s = protocol.solve(&k, &c, &x);

        let result = protocol.verify(&r1, &r2, &y1, &y2, &c, &s);

        assert!(
            result,
            "Verification should have succeeded even with random inputs."
        );
    }

    #[test]
    fn test_schnorr_protocol_fake_secret_fails() {
        let p = BigUint::from(23u32);
        let q = BigUint::from(11u32);
        let alpha = BigUint::from(4u32);
        let beta = BigUint::from(9u32);

        let protocol = SchnorrProtocol::new(p.clone(), q.clone(), alpha.clone(), beta.clone());

        let x = BigUint::from(6u32);
        let k = generate_random_below(&q);
        let y1 = exponentiate(&alpha, &x, &p);
        let y2 = exponentiate(&beta, &x, &p);
        let r1 = exponentiate(&alpha, &k, &p);
        let r2 = exponentiate(&beta, &k, &p);
        let c = generate_random_below(&q);

        let fake_secret = BigUint::from(7u32);
        let fake_s = protocol.solve(&k, &c, &fake_secret);

        let fake_result = protocol.verify(&r1, &r2, &y1, &y2, &c, &fake_s);

        assert!(
            !fake_result,
            "Verification should have failed with a fake secret."
        );
    }
}
