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

use crate::errors::Errors;
use serde::{Deserialize, Serialize};
use std::fmt::{self, Display, Formatter};
use std::str::FromStr;

/// Whether credentials of a type also require the issuer to remain authorised
/// in the current version ([`Validity::Current`]) or whether the authorisation
/// state at the moment of issuance is sufficient ([`Validity::PointInTime`]).
#[derive(Debug, Serialize, Deserialize, Clone)]
pub enum Validity {
    #[serde(rename = "point-in-time")]
    PointInTime,
    #[serde(rename = "current")]
    Current,
}

impl FromStr for Validity {
    type Err = Errors;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "point-in-time" => Ok(Validity::PointInTime),
            "current" => Ok(Validity::Current),
            validity => Err(Errors::format(
                format!("Invalid Validity: {}", validity),
                None,
            )),
        }
    }
}

impl Display for Validity {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        let s = match self {
            Validity::PointInTime => "point-in-time",
            Validity::Current => "current",
        };

        write!(f, "{s}")
    }
}
