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

//! Actors of the VDS protocol.
//!
//! - [`Anchor`] — a trust anchor as declared inside a VDS's `trustAnchors`
//!   list. Has a DID, an HTTPS endpoint where the anchor publishes its
//!   VAD, and a `vad` flag indicating whether a VAD exists.
//! - [`Issuer`] — an issuer as declared inside a VAD's `issuers` list.
//!   Holds the credential types it is authorised to issue.
//!
//! The `issuer` property of a Verifiable Credential is a different concept
//! defined by the W3C, and lives in [`crate::types::vcs::VcIssuer`].

mod anchor;
mod issuer;
pub use anchor::Anchor;
pub use issuer::Issuer;
