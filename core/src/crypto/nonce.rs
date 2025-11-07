use crabgraph::rand::secure_bytes;

const NONCE_SIZE: usize = 32;
const MIN_NONCE_LEN: usize = 16;
const MAX_NONCE_LEN: usize = 128;

/// Generate a cryptographically secure random nonce
pub fn generate_nonce() -> Vec<u8> {
    // Note: This should never fail with a working OS RNG
    secure_bytes(NONCE_SIZE).expect("RNG failure - OS entropy source unavailable")
}

pub fn validate_nonce(nonce: &[u8]) -> bool {
    let len = nonce.len();
    len >= MIN_NONCE_LEN && len <= MAX_NONCE_LEN
}
