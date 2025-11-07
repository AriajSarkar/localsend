/// Compute SHA-256 hash of the given data
#[inline]
pub fn sha256(data: &[u8]) -> Vec<u8> {
    crabgraph::sha256(data).to_vec()
}
