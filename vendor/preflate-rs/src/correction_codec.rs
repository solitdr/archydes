/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the Apache License, Version 2.0. See LICENSE.txt in the project root for license information.
 *  This software incorporates material from third parties. See NOTICE.txt for details.
 *--------------------------------------------------------------------------------------------*/

//! Archydes fork: the bit-level coding uses `crate::range_coder` instead of the LGPL `cabac`
//! crate (see FORK.md). The collection of actions is unchanged from upstream.

use crate::{
    bit_helper::bit_length,
    range_coder::{Prob, RangeDecoder, RangeEncoder},
    statistical_codec::{
        CodecCorrection, CountNonDefaultActions, PredictionDecoder, PredictionEncoder,
    },
};

/// calculates the difference between two values, keeping track
/// of the sign as the lowest bit so that the difference is never negative
pub fn encode_difference(pred_val: u32, act_val: u32) -> u32 {
    if pred_val >= act_val {
        (pred_val - act_val) << 1
    } else {
        ((act_val - pred_val) << 1) | 1
    }
}

/// decodes the result of the previous calculation
pub fn decode_difference(pred_val: u32, encoded_val: u32) -> u32 {
    if encoded_val & 1 == 0 {
        pred_val - (encoded_val >> 1)
    } else {
        pred_val + (encoded_val >> 1)
    }
}

#[test]
fn test_encode_decode_difference() {
    for i in 0..10 {
        assert_eq!(i, decode_difference(0, encode_difference(0, i)));
        assert_eq!(i, decode_difference(10, encode_difference(10, i)));
        assert_eq!(i, decode_difference(100, encode_difference(100, i)));
    }
}

const MAX: usize = CodecCorrection::MAX as usize;

/// Contexts per correction type: whether a run of defaults or a correction follows, and the
/// exponent/mantissa contexts for run lengths and correction values.
struct Contexts {
    default_signal: [Prob; MAX],
    default_exp: [[Prob; 32]; MAX],
    default_bits: [[Prob; 32]; MAX],
    correction_exp: [[Prob; 32]; MAX],
    correction_bits: [[Prob; 32]; MAX],
}

impl Default for Contexts {
    fn default() -> Self {
        Contexts {
            default_signal: [Prob::default(); MAX],
            default_exp: [[Prob::default(); 32]; MAX],
            default_bits: [[Prob::default(); 32]; MAX],
            correction_exp: [[Prob::default(); 32]; MAX],
            correction_bits: [[Prob::default(); 32]; MAX],
        }
    }
}

/// Elias-gamma style: bit length in unary, then the bits below the leading one.
fn write_exp(w: &mut RangeEncoder, value: u32, exp: &mut [Prob; 32], bits: &mut [Prob; 32]) {
    let bl = bit_length(value) as usize;
    w.unary(bl, exp, 32);
    if bl > 1 {
        w.bits(value as u64, bl - 1, bits);
    }
}

fn read_exp(r: &mut RangeDecoder, exp: &mut [Prob; 32], bits: &mut [Prob; 32]) -> u32 {
    match r.unary(exp, 32) {
        0 => 0,
        1 => 1,
        bl => (r.bits(bl - 1, bits) as u32) | (1 << (bl - 1)),
    }
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
enum Actions {
    Default(CodecCorrection, u32),
    Correction(CodecCorrection, u32),
}

pub struct PredictionEncoderRc<'a> {
    context: Contexts,
    actions: Vec<Actions>,
    last_action: [Option<usize>; MAX],
    action_seen: [bool; MAX],
    count: CountNonDefaultActions,
    writer: RangeEncoder<'a>,
}

impl<'a> PredictionEncoderRc<'a> {
    pub fn new(out: &'a mut Vec<u8>) -> Self {
        Self {
            context: Contexts::default(),
            writer: RangeEncoder::new(out),
            actions: Default::default(),
            last_action: Default::default(),
            count: CountNonDefaultActions::default(),
            action_seen: Default::default(),
        }
    }

    /// for debugging
    #[allow(dead_code)]
    pub fn print(&self) {
        self.count.print();
    }
}

impl PredictionEncoder for PredictionEncoderRc<'_> {
    fn encode_verify_state(&mut self, _message: &'static str, _checksum: u64) {}

    fn encode_correction(&mut self, c: CodecCorrection, value: u32) {
        let i = c as usize;

        // if it is a non-zero correction, then we just insert it
        if value != 0 {
            self.last_action[i] = Some(self.actions.len());
            self.actions.push(Actions::Correction(c, value));
            self.action_seen[i] = true;

            self.count.record_correction(c, value);
            return;
        }

        // otherwise we look to see if the last action was a default action
        // and if so, just increment it
        if let Some(l) = self.last_action[i] {
            let a = &mut self.actions[l];
            if let Actions::Default(_, x) = a {
                *x += 1;
                return;
            }
        }

        // otherwise we add a new default action
        self.last_action[i] = Some(self.actions.len());
        self.actions.push(Actions::Default(c, 1));
    }

    fn finish(&mut self) {
        // Written only now, in the order the decoder will ask for them.
        let mut seen_ctx = Prob::default();
        for &s in self.action_seen.iter() {
            self.writer.bit(s, &mut seen_ctx);
        }
        let ctx = &mut self.context;
        for &a in self.actions.iter() {
            match a {
                Actions::Default(c, value) => {
                    let i = c as usize;
                    if self.action_seen[i] {
                        self.writer.bit(true, &mut ctx.default_signal[i]);
                        write_exp(&mut self.writer, value - 1, &mut ctx.default_exp[i], &mut ctx.default_bits[i]);
                    }
                }
                Actions::Correction(c, value) => {
                    let i = c as usize;
                    self.writer.bit(false, &mut ctx.default_signal[i]);
                    write_exp(&mut self.writer, value - 1, &mut ctx.correction_exp[i], &mut ctx.correction_bits[i]);
                }
            }
        }
        self.writer.finish();
    }
}

pub struct PredictionDecoderRc<'a> {
    context: Contexts,
    reader: RangeDecoder<'a>,
    actions_seen: [bool; MAX],
    default_actions: [u32; MAX],
}

impl<'a> PredictionDecoderRc<'a> {
    pub fn new(input: &'a [u8]) -> Self {
        let mut reader = RangeDecoder::new(input);
        let mut actions_seen = [false; MAX];
        let mut seen_ctx = Prob::default();
        for s in actions_seen.iter_mut() {
            *s = reader.bit(&mut seen_ctx);
        }
        Self { context: Contexts::default(), default_actions: [0; MAX], actions_seen, reader }
    }

    #[cold]
    fn decode_correction_slow(&mut self, c: usize) -> u32 {
        let ctx = &mut self.context;
        if self.reader.bit(&mut ctx.default_signal[c]) {
            // A run of defaults: this one plus `run` more.
            let run = read_exp(&mut self.reader, &mut ctx.default_exp[c], &mut ctx.default_bits[c]);
            self.default_actions[c] = run;
            0
        } else {
            read_exp(&mut self.reader, &mut ctx.correction_exp[c], &mut ctx.correction_bits[c]).wrapping_add(1)
        }
    }
}

impl PredictionDecoder for PredictionDecoderRc<'_> {
    fn decode_verify_state(&mut self, _message: &'static str, _checksum: u64) {}

    #[inline]
    fn decode_correction(&mut self, correction: CodecCorrection) -> u32 {
        let c = correction as usize;
        // never seen: always the default
        if !self.actions_seen[c] {
            return 0;
        }
        // still inside a run of defaults
        if self.default_actions[c] > 0 {
            self.default_actions[c] -= 1;
            return 0;
        }
        self.decode_correction_slow(c)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::statistical_codec::{drive_encoder, verify_decoder, CodecAction};

    /// Corrections of all types, long default runs, large values, interleaved.
    fn actions(seed: u64, n: usize) -> Vec<CodecAction> {
        let mut s = seed;
        let mut next = move || {
            s ^= s << 13;
            s ^= s >> 7;
            s ^= s << 17;
            s
        };
        let types = [
            CodecCorrection::TokenCount,
            CodecCorrection::LenCorrection,
            CodecCorrection::DistOnlyCorrection,
            CodecCorrection::LiteralPredictionWrong,
            CodecCorrection::ReferencePredictionWrong,
            CodecCorrection::UncompressBlockLenCorrection,
        ];
        (0..n)
            .map(|_| {
                let r = next();
                let c = types[(r % types.len() as u64) as usize];
                let value = match (r >> 8) % 16 {
                    0 => (r >> 20) as u32,
                    1..=3 => ((r >> 20) % 300) as u32,
                    _ => 0,
                };
                if (r >> 40) % 50 == 0 {
                    CodecAction::VerifyState("check", r)
                } else {
                    CodecAction::Correction(c, value)
                }
            })
            .collect()
    }

    fn encode(a: &[CodecAction]) -> Vec<u8> {
        let mut out = Vec::new();
        let mut e = PredictionEncoderRc::new(&mut out);
        drive_encoder(&mut e, a);
        e.finish();
        drop(e);
        out
    }

    #[test]
    fn round_trip() {
        for seed in 1..20 {
            let a = actions(seed * 977, 20_000);
            let out = encode(&a);
            verify_decoder(&mut PredictionDecoderRc::new(&out), &a);
        }
        // Nothing but defaults costs next to nothing.
        let zeros = vec![CodecAction::Correction(CodecCorrection::LenCorrection, 0); 100_000];
        let out = encode(&zeros);
        assert!(out.len() < 16, "{}", out.len());
        verify_decoder(&mut PredictionDecoderRc::new(&out), &zeros);
    }

    /// Fixes the bytes of `ver = "preflate-rs-0.7.6/archydes-rc-1"`: if this changes, the
    /// correction data of existing archives can no longer be read.
    #[test]
    fn encoding_is_fixed() {
        let out = encode(&actions(42, 2_000));
        let sum = out.iter().fold(0xcbf29ce484222325u64, |h, &b| (h ^ b as u64).wrapping_mul(0x100000001b3));
        assert_eq!((out.len(), sum), (1439, 15966511958224244381));
    }

    #[test]
    fn garbage_does_not_panic() {
        let garbage: Vec<u8> = (0..4096u32).map(|i| (i.wrapping_mul(2654435761) >> 13) as u8).collect();
        let mut d = PredictionDecoderRc::new(&garbage);
        for i in 0..100_000 {
            let _ = d.decode_correction(if i % 3 == 0 {
                CodecCorrection::LenCorrection
            } else {
                CodecCorrection::LiteralPredictionWrong
            });
        }
    }
}
