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

//! Validity policy for credential types declared in a VDS.
//!
//! - [`Validity`] — whether a type is checked point-in-time or current.
//! - [`MaxValidity`] — the ceiling on a credential's lifetime, as an ISO 8601
//!   duration.
//!
//! See paper Section IV-B `validity` and `maxValidity` field semantics.

mod core;
mod max_validity;

pub use core::Validity;
pub use max_validity::MaxValidity;
