//! The nine fixed cubes (`90-analytics-telemetry.md §4.2`).
//!
//! Cubes are a **fixed set** — arbitrary dimension combinations would explode the sketch
//! count (O(2^n) sketches per day) and are rejected here, not just discouraged. Adding a
//! cube means a design review and a schema change, never a client-supplied string.

use alloc::string::String;
use alloc::vec::Vec;

/// Number of fixed cubes (`cube_0` ..= `cube_8`).
pub const CUBE_COUNT: u8 = 9;

/// Maximum length of a single dimension value, in bytes.
pub const MAX_DIM_VALUE_LEN: usize = 256;

/// Maximum length of an encoded cube key, in bytes.
pub const MAX_CUBE_KEY_LEN: usize = 1024;

/// Dimension names per cube index, in order.
const CUBE_DIMENSIONS: [&[&str]; CUBE_COUNT as usize] = [
    &["product"],
    &["product", "app_version"],
    &["product", "os", "arch"],
    &["product", "country"],
    &["product", "activation_path"],
    &["product", "mode"],
    &["product", "release_id"],
    &["product", "policy_id"],
    &["product", "sdk_version"],
];

/// A key into one day's sketches: which cube, plus its ordered dimension values.
///
/// Invariants (enforced by [`CubeKey::new`] and [`CubeKey::parse`], private fields):
/// the cube index is < [`CUBE_COUNT`], the dimension count matches the cube, and no
/// dimension value is empty, oversized, or contains the `|` separator.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct CubeKey {
    cube: u8,
    dims: Vec<String>,
}

/// Why a cube key was rejected.
#[derive(Clone, PartialEq, Eq, Debug)]
#[non_exhaustive]
pub enum CubeKeyError {
    /// Cube index is not in `0..CUBE_COUNT`.
    UnknownCube(u8),
    /// The encoded form does not look like `cube_<n>|<dim>|...`.
    Malformed,
    /// Dimension count does not match the cube's fixed arity.
    WrongDimensionCount {
        /// Cube index.
        cube: u8,
        /// Expected arity.
        expected: usize,
        /// Supplied arity.
        got: usize,
    },
    /// A dimension value was empty.
    EmptyDimension,
    /// A dimension value exceeded [`MAX_DIM_VALUE_LEN`].
    DimensionTooLong,
    /// A dimension value contained the `|` separator.
    InvalidCharacter,
    /// The encoded key exceeded [`MAX_CUBE_KEY_LEN`].
    KeyTooLong,
}

impl core::fmt::Display for CubeKeyError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::UnknownCube(c) => write!(f, "unknown cube index {c}; only cube_0..cube_8 exist"),
            Self::Malformed => write!(f, "malformed cube key; expected `cube_<n>|<dim>|...`"),
            Self::WrongDimensionCount {
                cube,
                expected,
                got,
            } => write!(f, "cube_{cube} takes {expected} dimension(s), got {got}"),
            Self::EmptyDimension => write!(f, "dimension values must not be empty"),
            Self::DimensionTooLong => {
                write!(f, "dimension value exceeds {MAX_DIM_VALUE_LEN} bytes")
            }
            Self::InvalidCharacter => {
                write!(f, "dimension values must not contain the `|` separator")
            }
            Self::KeyTooLong => write!(f, "encoded cube key exceeds {MAX_CUBE_KEY_LEN} bytes"),
        }
    }
}

fn check_dims(cube: u8, dims: &[String]) -> Result<(), CubeKeyError> {
    let names: &[&str] = CUBE_DIMENSIONS
        .get(usize::from(cube))
        .ok_or(CubeKeyError::UnknownCube(cube))?;
    if names.len() != dims.len() {
        return Err(CubeKeyError::WrongDimensionCount {
            cube,
            expected: names.len(),
            got: dims.len(),
        });
    }
    for d in dims {
        if d.is_empty() {
            return Err(CubeKeyError::EmptyDimension);
        }
        if d.len() > MAX_DIM_VALUE_LEN {
            return Err(CubeKeyError::DimensionTooLong);
        }
        if d.contains('|') {
            return Err(CubeKeyError::InvalidCharacter);
        }
    }
    Ok(())
}

impl CubeKey {
    /// Build a key, validating the cube index and its fixed dimension arity.
    pub fn new(cube: u8, dims: Vec<String>) -> Result<Self, CubeKeyError> {
        check_dims(cube, &dims)?;
        Ok(Self { cube, dims })
    }

    /// The cube index, `0..CUBE_COUNT`.
    #[must_use]
    pub fn cube_index(&self) -> u8 {
        self.cube
    }

    /// The ordered dimension values.
    #[must_use]
    pub fn dimensions(&self) -> &[String] {
        &self.dims
    }

    /// The cube's dimension names, in order.
    #[must_use]
    pub fn dimension_names(&self) -> &'static [&'static str] {
        // Validated at construction, so the index always exists.
        CUBE_DIMENSIONS
            .get(usize::from(self.cube))
            .copied()
            .unwrap_or(&[])
    }

    /// Stable encoding for the `analytics_hll.cube_key` TEXT column:
    /// `cube_<n>|<dim>|...` (e.g. `cube_2|my-app|linux|x86_64`).
    #[must_use]
    pub fn encode(&self) -> String {
        let mut out = alloc::format!("cube_{}", self.cube);
        for d in &self.dims {
            out.push('|');
            out.push_str(d);
        }
        out
    }

    /// Parse an encoded key, rejecting unknown cube indices, wrong dimension counts,
    /// and out-of-bounds input. Never panics on adversarial input.
    pub fn parse(encoded: &str) -> Result<Self, CubeKeyError> {
        if encoded.len() > MAX_CUBE_KEY_LEN {
            return Err(CubeKeyError::KeyTooLong);
        }
        let mut parts = encoded.split('|');
        let head = parts.next().ok_or(CubeKeyError::Malformed)?;
        let cube: u8 = head
            .strip_prefix("cube_")
            .ok_or(CubeKeyError::Malformed)?
            .parse()
            .map_err(|_| CubeKeyError::Malformed)?;
        let dims: Vec<String> = parts.map(String::from).collect();
        Self::new(cube, dims)
    }
}

#[cfg(feature = "serde")]
impl serde::Serialize for CubeKey {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.encode())
    }
}

#[cfg(feature = "serde")]
impl<'de> serde::Deserialize<'de> for CubeKey {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = <String as serde::Deserialize>::deserialize(deserializer)?;
        Self::parse(&s).map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::string::ToString;

    fn key(cube: u8, dims: &[&str]) -> CubeKey {
        CubeKey::new(cube, dims.iter().map(|d| (*d).to_string()).collect()).unwrap()
    }

    #[test]
    fn all_nine_cubes_round_trip() {
        let cases: [(u8, &[&str]); 9] = [
            (0, &["my-app"]),
            (1, &["my-app", "1.4.2"]),
            (2, &["my-app", "linux", "x86_64"]),
            (3, &["my-app", "DE"]),
            (4, &["my-app", "offline_ar"]),
            (5, &["my-app", "E"]),
            (6, &["my-app", "rel_01J"]),
            (7, &["my-app", "pol_pro"]),
            (8, &["my-app", "0.9.0"]),
        ];
        for (cube, dims) in cases {
            let k = key(cube, dims);
            assert_eq!(k.cube_index(), cube);
            assert_eq!(k.dimensions().len(), dims.len());
            let parsed = CubeKey::parse(&k.encode()).unwrap();
            assert_eq!(parsed, k);
        }
    }

    #[test]
    fn the_encoding_is_stable() {
        assert_eq!(
            key(2, &["my-app", "linux", "x86_64"]).encode(),
            "cube_2|my-app|linux|x86_64"
        );
        assert_eq!(key(0, &["my-app"]).encode(), "cube_0|my-app");
    }

    #[test]
    fn dimension_names_match_the_design() {
        assert_eq!(key(0, &["p"]).dimension_names(), &["product"]);
        assert_eq!(
            key(2, &["p", "linux", "x86_64"]).dimension_names(),
            &["product", "os", "arch"]
        );
        assert_eq!(
            key(8, &["p", "0.9.0"]).dimension_names(),
            &["product", "sdk_version"]
        );
    }

    #[test]
    fn unknown_cube_indices_are_rejected() {
        assert_eq!(
            CubeKey::parse("cube_9|my-app"),
            Err(CubeKeyError::UnknownCube(9))
        );
        assert_eq!(
            CubeKey::parse("cube_255|my-app"),
            Err(CubeKeyError::UnknownCube(255))
        );
        assert!(matches!(
            CubeKey::parse("cube_x|my-app"),
            Err(CubeKeyError::Malformed)
        ));
        assert!(matches!(
            CubeKey::parse("notacube|my-app"),
            Err(CubeKeyError::Malformed)
        ));
        assert!(matches!(CubeKey::parse(""), Err(CubeKeyError::Malformed)));
    }

    #[test]
    fn wrong_dimension_counts_are_rejected() {
        assert_eq!(
            CubeKey::parse("cube_0|my-app|extra"),
            Err(CubeKeyError::WrongDimensionCount {
                cube: 0,
                expected: 1,
                got: 2
            })
        );
        assert_eq!(
            CubeKey::parse("cube_2|my-app|linux"),
            Err(CubeKeyError::WrongDimensionCount {
                cube: 2,
                expected: 3,
                got: 2
            })
        );
        // Missing the dimension entirely leaves zero parts.
        assert_eq!(
            CubeKey::parse("cube_1"),
            Err(CubeKeyError::WrongDimensionCount {
                cube: 1,
                expected: 2,
                got: 0
            })
        );
    }

    #[test]
    fn empty_oversized_and_separator_dimensions_are_rejected() {
        assert_eq!(CubeKey::parse("cube_0|"), Err(CubeKeyError::EmptyDimension));
        let long = "x".repeat(MAX_DIM_VALUE_LEN + 1);
        assert_eq!(
            CubeKey::parse(&alloc::format!("cube_0|{long}")),
            Err(CubeKeyError::DimensionTooLong)
        );
        // A `|` inside a value shifts the arity, so it is caught by construction too.
        assert_eq!(
            CubeKey::new(0, alloc::vec!["a|b".to_string()]),
            Err(CubeKeyError::InvalidCharacter)
        );
    }

    #[test]
    fn overlong_keys_are_rejected() {
        let long = "x".repeat(MAX_CUBE_KEY_LEN);
        assert_eq!(
            CubeKey::parse(&alloc::format!("cube_0|{long}")),
            Err(CubeKeyError::KeyTooLong)
        );
    }
}
