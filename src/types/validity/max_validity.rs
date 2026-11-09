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
use crate::impl_serde_via_str;
use chrono::{DateTime, Days, Months, Utc};
use std::fmt::{Display, Formatter};
use std::str::FromStr;

/// A ceiling on credential lifetime, declared per credential type as an ISO 8601
/// duration restricted to the date components (years, months, days).
///
/// The original text is kept verbatim: this value sits inside the canonicalised,
/// hashed VDS content, so `Display` must reproduce exactly what was parsed, or the
/// version digest would change.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MaxValidity {
    raw: String,
    months: u32, // years folded in (1Y = 12M)
    days: u32,
}

impl MaxValidity {
    /// Whether a credential's declared window fits under this ceiling.
    ///
    /// The duration is applied to `valid_from` with calendar-aware arithmetic
    /// (a month is not a fixed number of days), hence chrono's `Months`/`Days`
    /// rather than a fixed span.
    pub fn admits(&self, valid_from: DateTime<Utc>, valid_until: DateTime<Utc>) -> bool {
        let ceiling = valid_from + Months::new(self.months) + Days::new(self.days as u64);
        valid_until <= ceiling
    }
}

impl Display for MaxValidity {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.raw)
    }
}

impl FromStr for MaxValidity {
    type Err = Errors;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let body = s
            .strip_prefix('P')
            .ok_or_else(|| Errors::format(format!("Duration must start with 'P': {s}"), None))?;

        if body.is_empty() || body.contains('T') {
            return Err(Errors::format(
                format!("Unsupported duration (date components only): {s}"),
                None,
            ));
        }

        let (mut years, mut months, mut days) = (0u32, 0u32, 0u32);
        let mut num = String::new();
        let mut seen = String::new();

        for c in body.chars() {
            if c.is_ascii_digit() {
                num.push(c);
                continue;
            }
            if num.is_empty() {
                return Err(Errors::format(format!("Malformed duration: {s}"), None));
            }
            let value: u32 = num
                .parse()
                .map_err(|_| Errors::format(format!("Duration value out of range: {s}"), None))?;
            num.clear();

            match c {
                'Y' if !seen.contains('Y') => years = value,
                'M' if !seen.contains('M') => months = value,
                'D' if !seen.contains('D') => days = value,
                _ => return Err(Errors::format(format!("Malformed duration: {s}"), None)),
            }
            seen.push(c);
        }

        if !num.is_empty() {
            return Err(Errors::format(format!("Duration value without unit: {s}"), None));
        }

        Ok(MaxValidity {
            raw: s.to_string(),
            months: years * 12 + months,
            days,
        })
    }
}

impl_serde_via_str!(MaxValidity);
