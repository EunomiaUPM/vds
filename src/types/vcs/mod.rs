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
//! Verifiable Credential types following the W3C VC Data Model 2.0.
//!
//! The central type is [`VcDocument`]. The remaining types model optional
//! fields of a VC:
//!
//! - [`TermsOfUse`] — links the credential to a governing VDS via its
//!   content-addressed `version`. This is the integration point with the VDS
//!   protocol.
//! - [`VcIssuer`] — the `issuer` property, either a URL or an object.
//! - [`VcSchema`], [`VcStatus`], [`VcEvidence`], [`VcRefreshService`] —
//!   standard W3C VC fields.
//! - [`DsParticipantCredSub`] — the `credentialSubject` shape for a
//!   Data Space Participant credential (specific to the paper's example).
//! - [`VDSCredentialType`] — the schema entry declared inside a VDS's
//!   `credentialTypes` list.

mod ds_participant;
mod evidence;
mod refresh_service;
mod status;
mod terms_of_use;
mod vc_doc;
mod vc_issuer;
mod vc_schema;

pub use ds_participant::DsParticipantCredSub;
pub use evidence::VcEvidence;
pub use refresh_service::VcRefreshService;
pub use status::VcStatus;
pub use terms_of_use::{Delegation, TermsOfUse};
pub use vc_doc::VcDocument;
pub use vc_issuer::VcIssuer;
pub use vc_schema::VcSchema;
