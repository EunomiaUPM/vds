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

//! Verifiable Anchor Delegation — the per-anchor list of delegated issuers.
//!
//! A VAD is signed exclusively by a single trust anchor and declares the
//! set of issuers authorised to issue credentials under that anchor's
//! scope. While the VDS represents the ecosystem-wide governance, the
//! VAD operates at the anchor level and can evolve independently of the
//! shared VDS.
//!
//! Identified by `vad:sha256:<digest>`, with a `vds` field pointing to
//! the VDS instance it belongs to.
//!
//! See paper Section IV-C and Listing 3.

mod vad_data;
mod core;
mod builder;

pub use vad_data::VadData;
pub use core::Vad;
pub use builder::*;