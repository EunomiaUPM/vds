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

//! Unified error type used across the crate.
//!
//! [`Errors`] is a single enum with semantic variants for the kinds of
//! failures the crate can produce. Each variant carries a common
//! [`ErrorStruct`] (message, reason, optional source, backtrace) plus
//! variant-specific fields where useful (`Request` carries `url`,
//! `method` and `status_code`).
//!
//! ## Variants
//!
//! - `Format` — malformed input that should have been well-formed
//!   (missing JSON field, wrong shape, ...).
//! - `Parse` — parsing failure of an encoded value (base64, base58, hex,
//!   PEM, JWK JSON, ...).
//! - `Invalid` — cryptographic validity failure (signature does not
//!   verify, key bytes invalid, ...).
//! - `NotSupported` — feature recognised but not implemented for the
//!   given input (unsupported curve, unsupported cryptosuite, ...).
//! - `Request` — outbound HTTP request failed (used by `did:web`).
//! - `Panic` — internal invariant violated; the helper constructor
//!   panics with a formatted log.
//!
//! ## Constructors
//!
//! Each variant has a corresponding lower-case helper:
//! [`Errors::format`], [`Errors::parse`], [`Errors::invalid`],
//! [`Errors::not_supported`], [`Errors::request`], [`Errors::panic`].
//!
//! ## Conventions
//!
//! - [`Outcome<T>`] is `Result<T, Errors>` and is the standard return
//!   type throughout the crate.
//! - [`AnyError`] is a `Box<dyn Error + Send + Sync>` used to chain
//!   external error sources.

mod constructor;
mod core;
mod helpers;
mod verification;

pub use verification::VerificationCause;
pub use core::*;
pub type AnyError = Box<dyn std::error::Error + Send + Sync>;
pub type Outcome<T> = Result<T, Errors>;
