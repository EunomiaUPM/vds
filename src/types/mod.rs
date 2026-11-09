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

//! Data models used by the VDS protocol.
//!
//! Each submodule groups a coherent set of types:
//!
//! - [`crypto`] — cryptographic primitives that appear in documents:
//!   [`crypto::Proof`] (W3C Data Integrity proof) and
//!   [`crypto::Canon`] (newtype enforcing JCS-canonicalised bytes at
//!   the type level).
//! - [`keys`] — key material: [`keys::ConfigKey`] (serializable key
//!   description), [`keys::StoredKey`] (in-memory, holds parsed
//!   native crypto types), [`keys::RetrievedKey`] (public-only,
//!   obtained from DID resolution), plus the JOSE discriminators
//!   [`keys::Kty`], [`keys::Crv`] and [`keys::Alg`].
//! - [`entities`] — actors of the system: [`entities::Anchor`] (trust
//!   anchor declared in a VDS) and [`entities::Issuer`] (declared in a
//!   VAD's `issuers` list).
//! - [`vds`] — the VDS governance artifact.
//! - [`vad`] — the Verifiable Anchor Delegation artifact.
//! - [`vcs`] — Verifiable Credentials following W3C VC Data Model 2.0
//!   (including the `termsOfUse` entry that binds a credential to a VDS).
//! - [`vp`] — Verifiable Presentations.
//! - [`jwt`] — JWT claim structures for VC-JWT and VP-JWT.
//! - [`validity`] — the `point-in-time` / `current` validity enum used
//!   in `credentialTypes`.

pub mod crypto;
pub mod dids;
pub mod entities;
mod identifier;
pub mod jwt;
pub mod keys;
pub mod validity;
pub mod vad;
pub mod vcs;
pub mod vds;
pub mod vps;

pub struct Missing;
pub struct Present;
pub use identifier::{ContentId, IdScheme};
