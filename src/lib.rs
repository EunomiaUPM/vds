/*
 * Copyright (C) 2026 - Universidad Politécnica de Madrid - UPM
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

//! Reference implementation and benchmark suite for the **Verifiable Data
//! Space (VDS)** governance model described in the accompanying paper.
//!
//! The crate is organised in four top-level modules:
//!
//! - [`types`] — data models for VDS, VAD, Verifiable Credentials and
//!   Verifiable Presentations, plus key material and JOSE/JWK types.
//! - [`capabilities`] — operational logic: signing, verification and DID
//!   resolution. Each capability is a unit struct exposing associated
//!   functions; state flows through arguments.
//! - [`errors`] — single `Errors` enum used across the crate, with helper
//!   constructors and an `Outcome<T>` alias for `Result<T, Errors>`.
//! - [`utils`] — shared infrastructure: JCS canonicalisation, base64url
//!   decoding, lazy HTTP client.
//!
//! The benchmark suite lives in `benches/benchmark.rs` and is run with
//! `cargo bench`.

pub mod capabilities;
pub mod errors;
pub mod fixtures;
pub mod types;
pub mod utils;
pub mod macros;
#[cfg(test)]
mod tests;
pub mod verifier;
