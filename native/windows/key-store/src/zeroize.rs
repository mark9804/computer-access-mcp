use std::ptr::write_volatile;
use std::sync::atomic::{compiler_fence, Ordering};

/// Overwrites every byte in `buf` using volatile writes followed by a compiler
/// fence so the compiler cannot elide clearing sensitive key material.
pub fn zeroize_slice(buf: &mut [u8]) {
    for byte in buf.iter_mut() {
        // SAFETY: `byte` is a valid, aligned, exclusively borrowed writable pointer.
        unsafe { write_volatile(byte, 0) };
    }
    compiler_fence(Ordering::SeqCst);
}

/// Fixed-size 32-byte plaintext master key that zeroizes itself on drop.
pub struct ZeroizingKey([u8; 32]);

impl ZeroizingKey {
    pub fn zeroed() -> Self {
        Self([0u8; 32])
    }

    pub fn from_slice(src: &[u8]) -> Option<Self> {
        if src.len() != 32 {
            return None;
        }
        let mut key = Self::zeroed();
        key.0.copy_from_slice(src);
        Some(key)
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    pub fn as_bytes_mut(&mut self) -> &mut [u8; 32] {
        &mut self.0
    }
}

impl Drop for ZeroizingKey {
    fn drop(&mut self) {
        zeroize_slice(&mut self.0);
    }
}

/// Fixed-size 44-byte base64 key buffer that zeroizes itself on drop.
pub struct ZeroizingBase64([u8; 44]);

impl ZeroizingBase64 {
    pub fn new(bytes: [u8; 44]) -> Self {
        Self(bytes)
    }

    pub fn as_bytes(&self) -> &[u8; 44] {
        &self.0
    }

    pub fn as_str(&self) -> &str {
        // SAFETY: `ZeroizingBase64` is only constructed from ASCII base64 bytes.
        std::str::from_utf8(&self.0).unwrap_or("")
    }
}

impl Drop for ZeroizingBase64 {
    fn drop(&mut self) {
        zeroize_slice(&mut self.0);
    }
}

/// Heap byte buffer that zeroizes its contents (including full initialized length) on drop.
pub struct ZeroizingVec(Vec<u8>);

impl ZeroizingVec {
    pub fn new(buf: Vec<u8>) -> Self {
        Self(buf)
    }

    pub fn as_slice(&self) -> &[u8] {
        &self.0
    }
}

impl Drop for ZeroizingVec {
    fn drop(&mut self) {
        zeroize_slice(&mut self.0);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn zeroize_slice_clears_all_bytes() {
        let mut buf = [0xAAu8; 32];
        zeroize_slice(&mut buf);
        assert_eq!(buf, [0u8; 32]);
    }
}
