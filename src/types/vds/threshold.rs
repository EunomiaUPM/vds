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

use crate::errors::{Errors, Outcome};
use crate::impl_serde_via_str;
use std::fmt::{Display, Formatter};
use std::str::FromStr;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Threshold {
    required: u16,
    total: u16,
}

impl Threshold {
    pub(crate) fn unset() -> Self {
        Self { required: 0, total: 0 }
    }
    /// The transition rule `t/n`: a successor needs valid proofs from at least
    /// `required` of the `total` anchors listed in the version it supersedes.
    pub fn new(required: u16, total: u16) -> Outcome<Self> {
        if required == 0 {
            return Err(Errors::invalid(
                format!("Threshold requires no signatures: {required}/{total}"),
                None,
            ));
        }
        if required > total {
            return Err(Errors::invalid(
                format!("Threshold requires more signatures than anchors: {required}/{total}"),
                None,
            ));
        }
        Ok(Self { required, total })
    }

    pub fn required(&self) -> u16 {
        self.required
    }

    pub fn total(&self) -> u16 {
        self.total
    }
}

impl Display for Threshold {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}/{}", self.required, self.total)
    }
}

impl FromStr for Threshold {
    type Err = Errors;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (t, n) = s
            .split_once('/')
            .ok_or_else(|| Errors::format(format!("Malformed threshold: {s}"), None))?;

        let required = t
            .parse()
            .map_err(|_| Errors::format(format!("Malformed threshold: {s}"), None))?;
        let total = n
            .parse()
            .map_err(|_| Errors::format(format!("Malformed threshold: {s}"), None))?;

        Self::new(required, total)
    }
}

impl_serde_via_str!(Threshold);
