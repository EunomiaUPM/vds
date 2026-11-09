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

use super::{ErrorStruct, Errors, VerificationCause};
use serde_json::Error as JsonError;
use tracing::error;

impl Errors {
    pub fn core(&self) -> &ErrorStruct {
        match self {
            Errors::Request { core, .. } => core,
            Errors::Format { core } => core,
            Errors::Parse { core } => core,
            Errors::NotSupported { core } => core,
            Errors::Invalid { core } => core,
            Errors::Verification { core, .. } => core,
        }
    }

    pub fn string_log(&self) -> String {
        let err = self.core();

        let source = match err.source.as_ref() {
            Some(data) => format!("\n {}", data),
            None => String::new(),
        };

        format!(
            "{} \n {} \n {} \n {}",
            self, err.reason, source, err.backtrace
        )
    }

    pub fn log(&self) {
        error!("{}", self.string_log());
    }

    pub fn cause(&self) -> Option<&VerificationCause> {
        match self {
            Errors::Verification { verification, .. } => Some(verification),
            _ => None,
        }
    }
}

impl From<JsonError> for Errors {
    fn from(error: JsonError) -> Self {
        Self::parse(error.to_string(), Some(Box::new(error)))
    }
}
