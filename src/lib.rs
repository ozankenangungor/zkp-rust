use num_bigint::{BigUint, RandBigInt};
use rand::Rng;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tracing::{info, instrument, warn};

/// Custom error type for ZKP operations
#[derive(Error, Debug)]
pub enum ZkpError {
    #[error("Invalid proof parameters")]
    InvalidProof,
    #[error("Serialization error: {0}")]
    SerializationError(String),
    #[error("Computation error: {0}")]
    ComputationError(String),
    #[error("Invalid input: {0}")]
    InvalidInput(String),
}

/// Result type for ZKP operations
pub type ZkpResult<T> = Result<T, ZkpError>;

/// Configuration for ZKP constants and parameters
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ZkpConfig {
    pub key_size_bits: usize,
    pub use_predefined_constants: bool,
}

impl Default for ZkpConfig {
    fn default() -> Self {
        Self {
            key_size_bits: 1024,
            use_predefined_constants: true,
        }
    }
}

/// Serialization utilities for BigUint
pub mod serialization {
    use super::*;

    /// Serialize BigUint to big-endian bytes
    #[instrument(skip(value))]
    pub fn serialize_biguint(value: &BigUint) -> Vec<u8> {
        let bytes = value.to_bytes_be();
        info!("Serialized BigUint with {} bytes", bytes.len());
        bytes
    }

    /// Deserialize BigUint from big-endian bytes
    #[instrument(skip(bytes))]
    pub fn deserialize_biguint(bytes: &[u8]) -> ZkpResult<BigUint> {
        if bytes.is_empty() {
            return Err(ZkpError::SerializationError("Empty byte array".to_string()));
        }
        let value = BigUint::from_bytes_be(bytes);
        info!("Deserialized BigUint from {} bytes", bytes.len());
        Ok(value)
    }
}

#[derive(Debug)]
pub struct ZKP {
    pub p: BigUint,
    pub q: BigUint,
    pub alpha: BigUint,
    pub beta: BigUint,
}

impl ZKP {
    /// Create a new ZKP instance with predefined constants or custom parameters
    #[instrument]
    pub fn new(config: Option<ZkpConfig>) -> ZkpResult<Self> {
        let config = config.unwrap_or_default();

        if config.use_predefined_constants {
            let (alpha, beta, p, q) = Self::get_constants();
            Ok(Self { p, q, alpha, beta })
        } else {
            // For custom parameters, you would generate or load them here
            Err(ZkpError::InvalidInput(
                "Custom parameters not implemented".to_string(),
            ))
        }
    }

    /// Improved compute_pair method that uses the struct's alpha and beta
    #[instrument(skip(self, exp))]
    pub fn compute_pair(&self, exp: &BigUint) -> ZkpResult<(BigUint, BigUint)> {
        if exp >= &self.q {
            return Err(ZkpError::InvalidInput(
                "Exponent must be less than q".to_string(),
            ));
        }

        let p1 = self.alpha.modpow(exp, &self.p);
        let p2 = self.beta.modpow(exp, &self.p);

        info!("Computed pair for exponent");
        Ok((p1, p2))
    }

    /// Improved solve method with better error handling
    #[instrument(skip(self, k, c, x))]
    pub fn solve(&self, k: &BigUint, c: &BigUint, x: &BigUint) -> ZkpResult<BigUint> {
        if k >= &self.q || c >= &self.q || x >= &self.q {
            return Err(ZkpError::InvalidInput(
                "All parameters must be less than q".to_string(),
            ));
        }

        let result = if *k >= c * x {
            (k - c * x).modpow(&BigUint::from(1u32), &self.q)
        } else {
            &self.q - (c * x - k).modpow(&BigUint::from(1u32), &self.q)
        };

        info!("Computed solution s");
        Ok(result)
    }

    /// Improved verify method with comprehensive validation
    #[instrument(skip(self, r1, r2, y1, y2, c, s))]
    pub fn verify(
        &self,
        r1: &BigUint,
        r2: &BigUint,
        y1: &BigUint,
        y2: &BigUint,
        c: &BigUint,
        s: &BigUint,
    ) -> ZkpResult<bool> {
        // Input validation
        if c >= &self.q || s >= &self.q {
            return Err(ZkpError::InvalidInput(
                "Challenge and solution must be less than q".to_string(),
            ));
        }

        if r1 >= &self.p || r2 >= &self.p || y1 >= &self.p || y2 >= &self.p {
            return Err(ZkpError::InvalidInput(
                "All commitments must be less than p".to_string(),
            ));
        }

        let cond1 = *r1
            == (&self.alpha.modpow(s, &self.p) * y1.modpow(c, &self.p))
                .modpow(&BigUint::from(1u32), &self.p);

        let cond2 = *r2
            == (&self.beta.modpow(s, &self.p) * y2.modpow(c, &self.p))
                .modpow(&BigUint::from(1u32), &self.p);

        let is_valid = cond1 && cond2;

        if is_valid {
            info!("Proof verification successful");
        } else {
            warn!("Proof verification failed");
        }

        Ok(is_valid)
    }

    /// Generate a cryptographically secure random number below the given bound
    #[instrument(skip(bound))]
    pub fn generate_random_number_below(bound: &BigUint) -> ZkpResult<BigUint> {
        if *bound == BigUint::from(0u32) {
            return Err(ZkpError::InvalidInput("Bound cannot be zero".to_string()));
        }

        let mut rng = rand::thread_rng();
        let random_num = rng.gen_biguint_below(bound);

        info!("Generated random number");
        Ok(random_num)
    }

    /// Generate a cryptographically secure random string of specified length
    #[instrument]
    pub fn generate_random_string(size: usize) -> ZkpResult<String> {
        if size == 0 {
            return Err(ZkpError::InvalidInput("Size cannot be zero".to_string()));
        }

        let random_string: String = rand::thread_rng()
            .sample_iter(rand::distributions::Alphanumeric)
            .take(size)
            .map(char::from)
            .collect();

        info!("Generated random string of length {}", size);
        Ok(random_string)
    }

    /// Get predefined cryptographic constants (1024-bit parameters)
    #[instrument]
    pub fn get_constants() -> (BigUint, BigUint, BigUint, BigUint) {
        let p = BigUint::from_bytes_be(&hex::decode("B10B8F96A080E01DDE92DE5EAE5D54EC52C99FBCFB06A3C69A6A9DCA52D23B616073E28675A23D189838EF1E2EE652C013ECB4AEA906112324975C3CD49B83BFACCBDD7D90C4BD7098488E9C219A73724EFFD6FAE5644738FAA31A4FF55BCCC0A151AF5F0DC8B4BD45BF37DF365C1A65E68CFDA76D4DA708DF1FB2BC2E4A4371").unwrap());
        let q = BigUint::from_bytes_be(
            &hex::decode("F518AA8781A8DF278ABA4E7D64B7CB9D49462353").unwrap(),
        );

        let alpha = BigUint::from_bytes_be(
            &hex::decode("A4D1CBD5C3FD34126765A442EFB99905F8104DD258AC507FD6406CFF14266D31266FEA1E5C41564B777E690F5504F213160217B4B01B886A5E91547F9E2749F4D7FBD7D3B9A92EE1909D0D2263F80A76A6A24C087A091F531DBF0A0169B6A28AD662A4D18E73AFA32D779D5918D08BC8858F4DCEF97C2A24855E6EEB22B3B2E5").unwrap(),
        );

        // beta = alpha^i is also a generator
        let exp = BigUint::from_bytes_be(&hex::decode("266FEA1E5C41564B777E69").unwrap());
        let beta = alpha.modpow(&exp, &p);

        (alpha, beta, p, q)
    }

    /// Validate that the ZKP parameters are cryptographically sound
    pub fn validate_parameters(&self) -> ZkpResult<()> {
        // Basic parameter validation
        if self.p <= BigUint::from(1u32) || self.q <= BigUint::from(1u32) {
            return Err(ZkpError::InvalidInput(
                "p and q must be greater than 1".to_string(),
            ));
        }

        if self.alpha >= self.p || self.beta >= self.p {
            return Err(ZkpError::InvalidInput(
                "Generators must be less than p".to_string(),
            ));
        }

        if self.alpha <= BigUint::from(1u32) || self.beta <= BigUint::from(1u32) {
            return Err(ZkpError::InvalidInput(
                "Generators must be greater than 1".to_string(),
            ));
        }

        info!("ZKP parameters validated successfully");
        Ok(())
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_toy_example() {
        let alpha = BigUint::from(4u32);
        let beta = BigUint::from(9u32);
        let p = BigUint::from(23u32);
        let q = BigUint::from(11u32);
        let zkp = ZKP {
            p: p.clone(),
            q,
            alpha: alpha.clone(),
            beta: beta.clone(),
        };

        let x = BigUint::from(6u32);
        let k = BigUint::from(7u32);
        let c = BigUint::from(4u32);

        let (y1, y2) = zkp.compute_pair(&x).unwrap();
        assert_eq!(y1, BigUint::from(2u32));
        assert_eq!(y2, BigUint::from(3u32));

        let (r1, r2) = zkp.compute_pair(&k).unwrap();
        assert_eq!(r1, BigUint::from(8u32));
        assert_eq!(r2, BigUint::from(4u32));

        let s = zkp.solve(&k, &c, &x).unwrap();
        assert_eq!(s, BigUint::from(5u32));

        let result = zkp.verify(&r1, &r2, &y1, &y2, &c, &s).unwrap();
        assert!(result);

        // fake secret
        let x_fake = BigUint::from(7u32);
        let s_fake = zkp.solve(&k, &c, &x_fake).unwrap();

        let result = zkp.verify(&r1, &r2, &y1, &y2, &c, &s_fake).unwrap();
        assert!(!result);
    }

    #[test]
    fn test_toy_example_with_random_numbers() {
        let alpha = BigUint::from(4u32);
        let beta = BigUint::from(9u32);
        let p = BigUint::from(23u32);
        let q = BigUint::from(11u32);
        let zkp = ZKP {
            p: p.clone(),
            q: q.clone(),
            alpha: alpha.clone(),
            beta: beta.clone(),
        };

        let x = BigUint::from(6u32);
        let k = ZKP::generate_random_number_below(&q).unwrap();
        let c = ZKP::generate_random_number_below(&q).unwrap();

        let (y1, y2) = zkp.compute_pair(&x).unwrap();
        assert_eq!(y1, BigUint::from(2u32));
        assert_eq!(y2, BigUint::from(3u32));

        let (r1, r2) = zkp.compute_pair(&k).unwrap();
        let s = zkp.solve(&k, &c, &x).unwrap();
        let result = zkp.verify(&r1, &r2, &y1, &y2, &c, &s).unwrap();
        assert!(result);
    }

    #[test]
    fn test_1024_bits_constants() {
        let zkp = ZKP::new(None).unwrap();
        let q = &zkp.q;

        let x = ZKP::generate_random_number_below(q).unwrap();
        let k = ZKP::generate_random_number_below(q).unwrap();
        let c = ZKP::generate_random_number_below(q).unwrap();

        let (y1, y2) = zkp.compute_pair(&x).unwrap();
        let (r1, r2) = zkp.compute_pair(&k).unwrap();
        let s = zkp.solve(&k, &c, &x).unwrap();
        let result = zkp.verify(&r1, &r2, &y1, &y2, &c, &s).unwrap();
        assert!(result);
    }

    #[test]
    fn test_serialization() {
        let value = BigUint::from(12345u32);
        let serialized = serialization::serialize_biguint(&value);
        let deserialized = serialization::deserialize_biguint(&serialized).unwrap();
        assert_eq!(value, deserialized);
    }

    #[test]
    fn test_error_handling() {
        let zkp = ZKP::new(None).unwrap();

        // Test invalid bounds
        let large_exp = &zkp.q + BigUint::from(1u32);
        assert!(zkp.compute_pair(&large_exp).is_err());

        // Test empty serialization
        assert!(serialization::deserialize_biguint(&[]).is_err());

        // Test zero bound for random generation
        assert!(ZKP::generate_random_number_below(&BigUint::from(0u32)).is_err());
    }
}
