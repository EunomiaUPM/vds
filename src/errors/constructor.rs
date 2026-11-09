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

use super::{AnyError, ErrorStruct, Errors, VerificationCause};
use std::backtrace::Backtrace;

impl Errors {
    pub fn request(
        url: impl Into<String>,
        method: impl Into<String>,
        code: impl Into<String>,
        reason: impl Into<String>,
        source: Option<AnyError>,
    ) -> Self {
        Errors::Request {
            core: ErrorStruct {
                message: "Request Error".to_string(),
                reason: reason.into(),
                source,
                backtrace: Backtrace::capture(),
            },
            url: url.into(),
            method: method.into(),
            status_code: code.into(),
        }
    }
    pub fn format(reason: impl Into<String>, source: Option<AnyError>) -> Self {
        Errors::Format {
            core: ErrorStruct {
                message: "Format Error".to_string(),
                reason: reason.into(),
                source,
                backtrace: Backtrace::capture(),
            },
        }
    }
    pub fn parse(reason: impl Into<String>, source: Option<AnyError>) -> Self {
        Errors::Parse {
            core: ErrorStruct {
                message: "Parse Error".to_string(),
                reason: reason.into(),
                source,
                backtrace: Backtrace::capture(),
            },
        }
    }
    pub fn not_supported(reason: impl Into<String>, source: Option<AnyError>) -> Self {
        Errors::NotSupported {
            core: ErrorStruct {
                message: "Feature not supported".to_string(),
                reason: reason.into(),
                source,
                backtrace: Backtrace::capture(),
            },
        }
    }
    pub fn invalid(reason: impl Into<String>, source: Option<AnyError>) -> Self {
        Errors::Invalid {
            core: ErrorStruct {
                message: "Invalid".to_string(),
                reason: reason.into(),
                source,
                backtrace: Backtrace::capture(),
            },
        }
    }
    pub fn verification(verification: VerificationCause) -> Self {
        Errors::Verification {
            core: ErrorStruct {
                message: "Verification Error".to_string(),
                reason: verification.to_string(),
                source: None,
                backtrace: Backtrace::capture(),
            },
            verification,
        }
    }
}
