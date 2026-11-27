/*---------------------------------------------------------------------------------------------
 *  Copyright (c) 2026 SOLIT SRL. Licensed under the Apache License, Version 2.0.
 *  Part of the Archydes fork of preflate-rs (see FORK.md); not from the original project.
 *--------------------------------------------------------------------------------------------*/

//! Adaptive binary range coder for the correction data.
//!
//! The well-known scheme also used by LZMA: 32-bit range, 11-bit probabilities that adapt by
//! 1/32 of the distance after every bit, carry propagation through a cached byte. Written from
//! the public description of that scheme; it replaces the LGPL `cabac` crate of upstream.
//!
//! Byte format: the encoder emits a leading zero byte, then the normalized output, and five
//! flush bytes at the end. The decoder reads missing bytes past the end as zero, so damaged
//! input decodes to garbage but never panics.

const PROB_BITS: u32 = 11;
const PROB_ONE: u16 = 1 << PROB_BITS;
const MOVE_BITS: u32 = 5;
const TOP: u32 = 1 << 24;

/// Probability that the next bit is 0, scaled to 2^11. Starts at 1/2.
#[derive(Clone, Copy, Debug)]
pub struct Prob(u16);

impl Default for Prob {
    fn default() -> Self {
        Prob(PROB_ONE / 2)
    }
}

pub struct RangeEncoder<'a> {
    out: &'a mut Vec<u8>,
    low: u64,
    range: u32,
    cache: u8,
    cache_size: u64,
}

impl<'a> RangeEncoder<'a> {
    pub fn new(out: &'a mut Vec<u8>) -> Self {
        RangeEncoder { out, low: 0, range: u32::MAX, cache: 0, cache_size: 1 }
    }

    fn shift_low(&mut self) {
        if (self.low as u32) < 0xff00_0000 || (self.low >> 32) != 0 {
            let carry = (self.low >> 32) as u8;
            let mut byte = self.cache;
            loop {
                self.out.push(byte.wrapping_add(carry));
                byte = 0xff;
                self.cache_size -= 1;
                if self.cache_size == 0 {
                    break;
                }
            }
            self.cache = ((self.low >> 24) & 0xff) as u8;
        }
        self.cache_size += 1;
        self.low = ((self.low as u32) << 8) as u64;
    }

    pub fn bit(&mut self, bit: bool, p: &mut Prob) {
        let bound = (self.range >> PROB_BITS) * p.0 as u32;
        if bit {
            self.low += bound as u64;
            self.range -= bound;
            p.0 -= p.0 >> MOVE_BITS;
        } else {
            self.range = bound;
            p.0 += (PROB_ONE - p.0) >> MOVE_BITS;
        }
        while self.range < TOP {
            self.range <<= 8;
            self.shift_low();
        }
    }

    /// `n` ones and a terminating zero, which is left out when `n == limit`; position `k` uses
    /// context `min(k, N-1)`. Decode with the same `limit`.
    pub fn unary<const N: usize>(&mut self, n: usize, ctx: &mut [Prob; N], limit: usize) {
        debug_assert!(n <= limit);
        for k in 0..n {
            self.bit(true, &mut ctx[k.min(N - 1)]);
        }
        // At the limit the decoder stops without reading a terminating zero.
        if n < limit {
            self.bit(false, &mut ctx[n.min(N - 1)]);
        }
    }

    /// The low `n` bits of `value`, most significant first; bit position `i` (counted from the
    /// top) uses context `min(i, N-1)`.
    pub fn bits<const N: usize>(&mut self, value: u64, n: usize, ctx: &mut [Prob; N]) {
        for i in 0..n {
            let bit = (value >> (n - 1 - i)) & 1 != 0;
            self.bit(bit, &mut ctx[i.min(N - 1)]);
        }
    }

    pub fn finish(&mut self) {
        for _ in 0..5 {
            self.shift_low();
        }
    }
}

pub struct RangeDecoder<'a> {
    input: &'a [u8],
    pos: usize,
    range: u32,
    code: u32,
}

impl<'a> RangeDecoder<'a> {
    pub fn new(input: &'a [u8]) -> Self {
        let mut d = RangeDecoder { input, pos: 0, range: u32::MAX, code: 0 };
        for _ in 0..5 {
            d.code = (d.code << 8) | d.byte() as u32;
        }
        d
    }

    fn byte(&mut self) -> u8 {
        let b = self.input.get(self.pos).copied().unwrap_or(0);
        self.pos += 1;
        b
    }

    pub fn bit(&mut self, p: &mut Prob) -> bool {
        let bound = (self.range >> PROB_BITS) * p.0 as u32;
        let bit = if self.code < bound {
            self.range = bound;
            p.0 += (PROB_ONE - p.0) >> MOVE_BITS;
            false
        } else {
            self.code -= bound;
            self.range -= bound;
            p.0 -= p.0 >> MOVE_BITS;
            true
        };
        while self.range < TOP {
            self.range <<= 8;
            self.code = (self.code << 8) | self.byte() as u32;
        }
        bit
    }

    /// Reads what [`RangeEncoder::unary`] wrote; stops at `limit` ones (hostile input).
    pub fn unary<const N: usize>(&mut self, ctx: &mut [Prob; N], limit: usize) -> usize {
        let mut n = 0;
        while n < limit && self.bit(&mut ctx[n.min(N - 1)]) {
            n += 1;
        }
        n
    }

    pub fn bits<const N: usize>(&mut self, n: usize, ctx: &mut [Prob; N]) -> u64 {
        let mut v = 0u64;
        for i in 0..n {
            v = (v << 1) | self.bit(&mut ctx[i.min(N - 1)]) as u64;
        }
        v
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_mixed() {
        let mut out = Vec::new();
        let mut seed = 12345u64;
        let mut rnd = || {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            seed
        };
        let items: Vec<(u64, usize)> = (0..20_000).map(|_| (rnd() & 0xfff, (rnd() % 41) as usize)).collect();
        {
            let mut e = RangeEncoder::new(&mut out);
            let (mut a, mut u, mut b) = (Prob::default(), [Prob::default(); 32], [Prob::default(); 32]);
            for &(v, n) in &items {
                e.bit(v & 1 == 1, &mut a);
                e.unary(n, &mut u, 40);
                e.bits(v, 12, &mut b);
            }
            e.finish();
        }
        let mut d = RangeDecoder::new(&out);
        let (mut a, mut u, mut b) = (Prob::default(), [Prob::default(); 32], [Prob::default(); 32]);
        for &(v, n) in &items {
            assert_eq!(d.bit(&mut a), v & 1 == 1);
            assert_eq!(d.unary(&mut u, 40), n);
            assert_eq!(d.bits(12, &mut b), v);
        }
    }

    #[test]
    fn skewed_bits_compress() {
        let mut out = Vec::new();
        let mut e = RangeEncoder::new(&mut out);
        let mut p = Prob::default();
        for i in 0..100_000 {
            e.bit(i % 100 == 0, &mut p);
        }
        e.finish();
        assert!(out.len() < 2_000, "{}", out.len());
    }

    #[test]
    fn garbage_does_not_panic() {
        let mut d = RangeDecoder::new(&[0xff, 0x13]);
        let mut u = [Prob::default(); 32];
        for _ in 0..1000 {
            let _ = d.unary(&mut u, 40);
        }
    }
}
