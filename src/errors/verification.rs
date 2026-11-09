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
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <https://www.gnu.org/licenses/>.
 */
use std::fmt::{Display, Formatter};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VerificationCause {
    // Content-addressing
    SchemeMismatch,
    VersionMismatch,
    GenesisIdMismatch,
    // Chain / Succession
    SuccessorIdMismatch,
    GenesisHasSupersedes,
    SupersedesMismatch,
    NotAllAnchorsSigned,
    ThresholdCountMismatch,
    ThresholdNotMet,
    // VAD
    VadNotSignedByOwner,
    VadWrongDataSpace,
    VadNotReferenced,
    // Binding
    BoundVersionAbsent,
    SignerNotIssuer,
    // Authorization
    DelegatingAnchorNotFound,
    AnchorDoesNotDelegate,
    IssuerNotAnchor,
    IssuerNotInVad,
    IssuerTypeNotAuthorized,
    TypeNotRecognised,
    // Temporal
    IssuedBeforeBound,
    WindowClosed,
    LifetimeExceedsMaxValidity,
}

impl Display for VerificationCause {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            // Content-addressing
            Self::SchemeMismatch => "Identifier scheme does not match the artifact type",
            Self::VersionMismatch => "Version identifier does not match the content",
            Self::GenesisIdMismatch => "Genesis id does not match the content",
            // Chain / Succession
            Self::SuccessorIdMismatch => "Successor id does not match the genesis id",
            Self::GenesisHasSupersedes => "A genesis cannot declare supersedes",
            Self::SupersedesMismatch => "Supersedes does not point to the previous version",
            Self::NotAllAnchorsSigned => "Not every listed anchor has signed",
            Self::ThresholdCountMismatch => "Threshold total does not match the anchor count",
            Self::ThresholdNotMet => "Successor is not signed by the required threshold",
            // VAD
            Self::VadNotSignedByOwner => "VAD is not signed by its owning anchor",
            Self::VadWrongDataSpace => "VAD dataSpace does not match the VDS",
            Self::VadNotReferenced => "No VDS anchor references this VAD genesis",
            // Binding
            Self::BoundVersionAbsent => "bound version is not present in the chain",
            Self::SignerNotIssuer => "Signer does not match the credential issuer",
            // Authorization
            Self::DelegatingAnchorNotFound => "Delegating anchor is not in the bound VDS",
            Self::AnchorDoesNotDelegate => "Anchor does not delegate to this VAD",
            Self::IssuerNotAnchor => "Issuer is not an anchor of the VDS",
            Self::IssuerNotInVad => "Issuer is not listed in the VAD",
            Self::IssuerTypeNotAuthorized => "Issuer is not authorised for this credential type",
            Self::TypeNotRecognised => "Credential type is not recognised by the VDS",
            // Temporal
            Self::IssuedBeforeBound => "Credential validFrom precedes its bound version",
            Self::WindowClosed => "Credential bound to a version whose issuance window has closed",
            Self::LifetimeExceedsMaxValidity => {
                "Credential lifetime exceeds the type's maxValidity"
            }
        };
        write!(f, "{s}")
    }
}
