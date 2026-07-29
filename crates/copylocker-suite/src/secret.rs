//! Secret material wrapper.

use core::fmt;

use subtle::ConstantTimeEq;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// A value that is wiped on drop and never rendered.
///
/// Per `crypto-architecture.md §8` this type intentionally does **not** implement `Debug`,
/// `Clone`, `Display`, or `PartialEq` in the usual way:
///
/// - no `Debug`/`Display`, so a stray `{:?}` cannot leak a key into a log;
/// - no `Clone`, so the number of copies in memory stays auditable;
/// - equality is constant-time only, via [`Secret::ct_eq`].
pub struct Secret<T: Zeroize>(T);

impl<T: Zeroize> Secret<T> {
    /// Wrap a value.
    pub fn new(v: T) -> Self {
        Self(v)
    }

    /// Borrow the protected value.
    ///
    /// The borrow is the only way out; there is deliberately no `into_inner` that would let the
    /// value escape the zeroizing wrapper.
    pub fn expose(&self) -> &T {
        &self.0
    }

    /// Mutable borrow, for in-place derivation into a fixed buffer.
    pub fn expose_mut(&mut self) -> &mut T {
        &mut self.0
    }
}

impl<const N: usize> Secret<[u8; N]> {
    /// A zero-filled secret of the given width, ready to be derived into.
    #[must_use]
    pub fn zeroed() -> Self {
        Self([0u8; N])
    }

    /// Constant-time equality. Never use `==` on key material.
    #[must_use]
    pub fn ct_eq(&self, other: &Self) -> bool {
        self.0.ct_eq(&other.0).into()
    }

    /// Borrow as a slice.
    #[must_use]
    pub fn as_slice(&self) -> &[u8] {
        &self.0
    }
}

impl<T: Zeroize> Drop for Secret<T> {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl<T: Zeroize> ZeroizeOnDrop for Secret<T> {}

impl<T: Zeroize> fmt::Debug for Secret<T> {
    /// Always renders a placeholder. This impl exists only so that structs containing a
    /// `Secret` can still derive `Debug` without leaking.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Secret(<redacted>)")
    }
}

/// A 256-bit symmetric key, the width used by every current slot.
pub type SecretKey = Secret<[u8; 32]>;

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::format;

    #[test]
    fn debug_never_reveals_contents() {
        let s: SecretKey = Secret::new([0xab; 32]);
        assert_eq!(format!("{s:?}"), "Secret(<redacted>)");
    }

    #[test]
    fn constant_time_equality_matches_value_equality() {
        let a: SecretKey = Secret::new([1u8; 32]);
        let b: SecretKey = Secret::new([1u8; 32]);
        let mut differs = [1u8; 32];
        differs[31] = 2;
        let c: SecretKey = Secret::new(differs);
        assert!(a.ct_eq(&b));
        assert!(!a.ct_eq(&c));
    }
}
