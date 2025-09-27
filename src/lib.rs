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

    #[test]
    fn test_schnorr_with_rfc3526_group2() {
        let p_hex = "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA237327FFFFFFFFFFFFFFFF";
        let p = BigUint::parse_bytes(p_hex.as_bytes(), 16).unwrap();

        // q = (p-1)/2
        let q = (&p - BigUint::from(1u32)) / BigUint::from(2u32);

        // alpha (g) = 2
        let alpha = BigUint::from(2u32);

        // beta = alpha^random mod p
        let random_power = generate_random_below(&q);
        let beta = alpha.modpow(&random_power, &p);

        let protocol = SchnorrProtocol::new(p.clone(), q.clone(), alpha.clone(), beta.clone());

        let x = generate_random_below(&q);
        let k = generate_random_below(&q);
        let c = generate_random_below(&q);

        let y1 = exponentiate(&alpha, &x, &p);
        let y2 = exponentiate(&beta, &x, &p);
        let r1 = exponentiate(&alpha, &k, &p);
        let r2 = exponentiate(&beta, &k, &p);
        let s = protocol.solve(&k, &c, &x);

        let result = protocol.verify(&r1, &r2, &y1, &y2, &c, &s);

        assert!(
            result,
            "Validation should have been successful with RFC 3526 Group 2 parameters."
        );
    }
}
