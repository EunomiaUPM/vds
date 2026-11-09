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

use crate::types::crypto::Proofed;

pub struct Chained<'a, T> {
    chain: &'a [Proofed<T>],
    bound: &'a Proofed<T>,
    next: Option<&'a Proofed<T>>,
    head: &'a Proofed<T>,
}

impl<'a, T> Chained<'a, T> {
    pub fn new(
        chain: &'a [Proofed<T>],
        bound: &'a Proofed<T>,
        next: Option<&'a Proofed<T>>,
        head: &'a Proofed<T>,
    ) -> Self {
        Self {
            chain,
            bound,
            next,
            head,
        }
    }
    pub fn chain(&self) -> &[Proofed<T>] {
        self.chain
    }
    pub fn bound(&self) -> &Proofed<T> {
        self.bound
    }
    pub fn next(&self) -> Option<&Proofed<T>> {
        self.next
    }
    pub fn head(&self) -> &Proofed<T> {
        self.head
    }
}
