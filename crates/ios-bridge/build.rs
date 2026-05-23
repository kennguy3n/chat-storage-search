//! UniFFI scaffolding generation for the iOS bridge.
//!
//! Reads the UDL at `src/kchat.udl` and emits the matching
//! Rust scaffolding into `OUT_DIR/kchat.uniffi.rs`. The
//! generated file is pulled into [`crate`] via the
//! `uniffi::include_scaffolding!("kchat")` macro at the bottom
//! of `src/lib.rs`.
//!
//! See for the iOS / Swift packaging
//! plan that consumes this scaffolding.

fn main() {
    uniffi::generate_scaffolding("src/kchat.udl").expect("UniFFI scaffolding for src/kchat.udl");
}
