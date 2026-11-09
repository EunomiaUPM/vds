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

use super::{AnyError, VerificationCause};
use std::backtrace::Backtrace;
use std::fmt::{Display, Formatter};

#[derive(Debug)]
pub enum Errors {
    Request {
        core: ErrorStruct,
        url: String,
        method: String,
        status_code: String,
    },
    Format {
        core: ErrorStruct,
    },
    Parse {
        core: ErrorStruct,
    },
    NotSupported {
        core: ErrorStruct,
    },
    Invalid {
        core: ErrorStruct,
    },
    Verification {
        core: ErrorStruct,
        verification: VerificationCause,
    },
}

#[derive(Debug)]
pub struct ErrorStruct {
    pub message: String,
    pub reason: String,
    pub source: Option<AnyError>,
    pub backtrace: Backtrace,
}

impl Display for Errors {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.core().message, self.core().reason)
    }
}

impl std::error::Error for Errors {}
