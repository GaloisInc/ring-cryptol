// Copyright 2019 Brian Smith.
//
// Permission to use, copy, modify, and/or distribute this software for any
// purpose with or without fee is hereby granted, provided that the above
// copyright notice and this permission notice appear in all copies.
//
// THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHORS DISCLAIM ALL WARRANTIES
// WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHORS BE LIABLE FOR ANY
// SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
// WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION
// OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN
// CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

use crate::c;
use core::{
    num::Wrapping,
    ops::{Add, AddAssign, BitAnd, BitOr, BitXor, Not, Shr},
};

#[cfg(not(any(target_arch = "aarch64", target_arch = "arm", target_arch = "x86_64")))]
pub(super) extern "C" fn GFp_sha256_block_data_order(
    state: &mut super::State,
    data: *const u8,
    num: c::size_t,
) {
    let state = unsafe { &mut state.as32 };
    *state = block_data_order(*state, data, num)
}

#[cfg(not(any(target_arch = "aarch64", target_arch = "arm", target_arch = "x86_64")))]
pub(super) extern "C" fn GFp_sha512_block_data_order(
    state: &mut super::State,
    data: *const u8,
    num: c::size_t,
) {
    let state = unsafe { &mut state.as64 };
    *state = block_data_order(*state, data, num)
}

#[cfg_attr(
    any(target_arch = "aarch64", target_arch = "arm", target_arch = "x86_64"),
    allow(dead_code)
)]
#[inline]
fn block_data_order<S: Sha2>(
    H: [S; CHAINING_WORDS],
    M: *const u8,
    num: c::size_t,
) -> [S; CHAINING_WORDS] {
    let M = M as *const [S::InputBytes; 16];
    let M: &[[S::InputBytes; 16]] = unsafe { core::slice::from_raw_parts(M, num) };
    block_data_order_slice::<S>(H, M)
}

#[inline]
fn block_data_order_slice<S: Sha2>(
    mut H: [S; CHAINING_WORDS],
    M: &[[S::InputBytes; 16]],
) -> [S; CHAINING_WORDS] {
    for M in M {
        // FIPS 180-4 {6.2.2, 6.4.2} Step 1
        //
        // TODO: Use `let W: [S::ZERO; S::ROUNDS]` instead of allocating
        // `MAX_ROUNDS` items and then slicing to `K.len()`; depends on
        // https://github.com/rust-lang/rust/issues/43408.
        let mut W = [S::ZERO; MAX_ROUNDS];
        let W: &[S] = {
            let W = &mut W[..S::K.len()];
            for (W, M) in W.iter_mut().zip(M) {
                *W = S::from_be_bytes(*M);
            }
            for t in M.len()..S::K.len() {
                W[t] = sigma_1(W[t - 2]) + W[t - 7] + sigma_0(W[t - 15]) + W[t - 16]
            }

            W
        };

        // FIPS 180-4 {6.2.2, 6.4.2} Step 2
        let mut a = H[0];
        let mut b = H[1];
        let mut c = H[2];
        let mut d = H[3];
        let mut e = H[4];
        let mut f = H[5];
        let mut g = H[6];
        let mut h = H[7];

        // FIPS 180-4 {6.2.2, 6.4.2} Step 3
        for (Kt, Wt) in S::K.iter().zip(W.iter()) {
            let T1 = h + SIGMA_1(e) + ch(e, f, g) + *Kt + *Wt;
            let T2 = SIGMA_0(a) + maj(a, b, c);
            h = g;
            g = f;
            f = e;
            e = d + T1;
            d = c;
            c = b;
            b = a;
            a = T1 + T2;
        }

        // FIPS 180-4 {6.2.2, 6.4.2} Step 4
        H[0] += a;
        H[1] += b;
        H[2] += c;
        H[3] += d;
        H[4] += e;
        H[5] += f;
        H[6] += g;
        H[7] += h;
    }

    H
}


// For verification, we define a word-based version of `block_data_order_slice` and decompose it
// into smaller functions we can override.

fn block_data_order_slice_words<S: Sha2>(
    mut H: [S; CHAINING_WORDS],
    M: &[[S; 16]],
) -> [S; CHAINING_WORDS] {
    for M in M {
        // FIPS 180-4 {6.2.2, 6.4.2} Step 1
        //
        // TODO: Use `let W: [S::ZERO; S::ROUNDS]` instead of allocating
        // `MAX_ROUNDS` items and then slicing to `K.len()`; depends on
        // https://github.com/rust-lang/rust/issues/43408.
        let W = message_schedule_words(M);
        let W = &W[..S::K.len()];

        H = compress_words(H, W);
    }

    H
}

fn message_schedule_words<S: Sha2>(
    M: &[S; 16],
) -> [S; MAX_ROUNDS] {
    let mut W = [S::ZERO; MAX_ROUNDS];
    {
        let W = &mut W[..S::K.len()];
        for (W, M) in W.iter_mut().zip(M) {
            *W = *M;
        }
        for t in M.len()..S::K.len() {
            W[t] = message_schedule_one(
                W[t - 2],
                W[t - 7],
                W[t - 15],
                W[t - 16],
            );
        }
    }
    W
}

fn message_schedule_one<S: Sha2>(
    a: S,
    b: S,
    c: S,
    d: S,
) -> S {
    sigma_1(a) + b + sigma_0(c) + d
}

fn compress_words<S: Sha2>(
    mut H: [S; CHAINING_WORDS],
    W: &[S],
) -> [S; CHAINING_WORDS] {
    // FIPS 180-4 {6.2.2, 6.4.2} Step 2
    let mut a = H[0];
    let mut b = H[1];
    let mut c = H[2];
    let mut d = H[3];
    let mut e = H[4];
    let mut f = H[5];
    let mut g = H[6];
    let mut h = H[7];

    // FIPS 180-4 {6.2.2, 6.4.2} Step 3
    assert_eq!(S::K.len(), W.len());
    for (Kt, Wt) in S::K.iter().zip(W.iter()) {
        let T1 = compress_t1(e, f, g, h, *Kt, *Wt);
        let T2 = compress_t2(a, b, c);
        h = g;
        g = f;
        f = e;
        e = d + T1;
        d = c;
        c = b;
        b = a;
        a = T1 + T2;
    }

    // FIPS 180-4 {6.2.2, 6.4.2} Step 4
    H[0] += a;
    H[1] += b;
    H[2] += c;
    H[3] += d;
    H[4] += e;
    H[5] += f;
    H[6] += g;
    H[7] += h;

    H
}

fn compress_t1<S: Sha2>(
    e: S,
    f: S,
    g: S,
    h: S,
    k_t: S,
    w_t: S,
) -> S {
    h + SIGMA_1(e) + ch(e, f, g) + k_t + w_t
}

fn compress_t2<S: Sha2>(
    a: S,
    b: S,
    c: S,
) -> S {
    SIGMA_0(a) + maj(a, b, c)
}


// FIPS 180-4 {4.1.1, 4.1.2, 4.1.3}
#[inline(always)]
pub(super) fn ch<W: Word>(x: W, y: W, z: W) -> W {
    (x & y) | (!x & z)
}

// FIPS 180-4 {4.1.1, 4.1.2, 4.1.3}
#[inline(always)]
pub(super) fn maj<W: Word>(x: W, y: W, z: W) -> W {
    (x & y) | (x & z) | (y & z)
}

// FIPS 180-4 {4.1.2, 4.1.3}
#[inline(always)]
fn SIGMA_0<S: Sha2>(x: S) -> S {
    x.rotr(S::BIG_SIGMA_0.0) ^ x.rotr(S::BIG_SIGMA_0.1) ^ x.rotr(S::BIG_SIGMA_0.2)
}

// FIPS 180-4 {4.1.2, 4.1.3}
#[inline(always)]
fn SIGMA_1<S: Sha2>(x: S) -> S {
    x.rotr(S::BIG_SIGMA_1.0) ^ x.rotr(S::BIG_SIGMA_1.1) ^ x.rotr(S::BIG_SIGMA_1.2)
}

// FIPS 180-4 {4.1.2, 4.1.3}
#[inline(always)]
fn sigma_0<S: Sha2>(x: S) -> S {
    x.rotr(S::SMALL_SIGMA_0.0) ^ x.rotr(S::SMALL_SIGMA_0.1) ^ (x >> S::SMALL_SIGMA_0.2)
}

// FIPS 180-4 {4.1.2, 4.1.3}
#[inline(always)]
fn sigma_1<S: Sha2>(x: S) -> S {
    x.rotr(S::SMALL_SIGMA_1.0) ^ x.rotr(S::SMALL_SIGMA_1.1) ^ (x >> S::SMALL_SIGMA_1.2)
}

// Commonality between SHA-1 and SHA-2 words.
pub(super) trait Word:
    'static
    + Sized
    + Copy
    + Add<Output = Self>
    + AddAssign
    + BitAnd<Output = Self>
    + BitOr<Output = Self>
    + Not<Output = Self>
{
    const ZERO: Self;

    type InputBytes: Copy;

    fn from_be_bytes(input: Self::InputBytes) -> Self;

    fn rotr(self, count: u32) -> Self;
}

/// A SHA-2 input word.
trait Sha2: Word + BitXor<Output = Self> + Shr<usize, Output = Self> {
    const BIG_SIGMA_0: (u32, u32, u32);
    const BIG_SIGMA_1: (u32, u32, u32);
    const SMALL_SIGMA_0: (u32, u32, usize);
    const SMALL_SIGMA_1: (u32, u32, usize);

    const K: &'static [Self];
}

const MAX_ROUNDS: usize = 80;
pub(super) const CHAINING_WORDS: usize = 8;

impl Word for Wrapping<u32> {
    const ZERO: Self = Wrapping(0);
    type InputBytes = [u8; 4];

    #[inline(always)]
    fn from_be_bytes(input: Self::InputBytes) -> Self {
        Wrapping(u32::from_be_bytes(input))
    }

    #[inline(always)]
    fn rotr(self, count: u32) -> Self {
        Wrapping(self.0.rotate_right(count))
    }
}

// SHA-256
impl Sha2 for Wrapping<u32> {
    // FIPS 180-4 4.1.2
    const BIG_SIGMA_0: (u32, u32, u32) = (2, 13, 22);
    const BIG_SIGMA_1: (u32, u32, u32) = (6, 11, 25);
    const SMALL_SIGMA_0: (u32, u32, usize) = (7, 18, 3);
    const SMALL_SIGMA_1: (u32, u32, usize) = (17, 19, 10);

    // FIPS 180-4 4.2.2
    const K: &'static [Self] = &[
        Self(0x428a2f98),
        Self(0x71374491),
        Self(0xb5c0fbcf),
        Self(0xe9b5dba5),
        Self(0x3956c25b),
        Self(0x59f111f1),
        Self(0x923f82a4),
        Self(0xab1c5ed5),
        Self(0xd807aa98),
        Self(0x12835b01),
        Self(0x243185be),
        Self(0x550c7dc3),
        Self(0x72be5d74),
        Self(0x80deb1fe),
        Self(0x9bdc06a7),
        Self(0xc19bf174),
        Self(0xe49b69c1),
        Self(0xefbe4786),
        Self(0x0fc19dc6),
        Self(0x240ca1cc),
        Self(0x2de92c6f),
        Self(0x4a7484aa),
        Self(0x5cb0a9dc),
        Self(0x76f988da),
        Self(0x983e5152),
        Self(0xa831c66d),
        Self(0xb00327c8),
        Self(0xbf597fc7),
        Self(0xc6e00bf3),
        Self(0xd5a79147),
        Self(0x06ca6351),
        Self(0x14292967),
        Self(0x27b70a85),
        Self(0x2e1b2138),
        Self(0x4d2c6dfc),
        Self(0x53380d13),
        Self(0x650a7354),
        Self(0x766a0abb),
        Self(0x81c2c92e),
        Self(0x92722c85),
        Self(0xa2bfe8a1),
        Self(0xa81a664b),
        Self(0xc24b8b70),
        Self(0xc76c51a3),
        Self(0xd192e819),
        Self(0xd6990624),
        Self(0xf40e3585),
        Self(0x106aa070),
        Self(0x19a4c116),
        Self(0x1e376c08),
        Self(0x2748774c),
        Self(0x34b0bcb5),
        Self(0x391c0cb3),
        Self(0x4ed8aa4a),
        Self(0x5b9cca4f),
        Self(0x682e6ff3),
        Self(0x748f82ee),
        Self(0x78a5636f),
        Self(0x84c87814),
        Self(0x8cc70208),
        Self(0x90befffa),
        Self(0xa4506ceb),
        Self(0xbef9a3f7),
        Self(0xc67178f2),
    ];
}

impl Word for Wrapping<u64> {
    const ZERO: Self = Wrapping(0);
    type InputBytes = [u8; 8];

    #[inline(always)]
    fn from_be_bytes(input: Self::InputBytes) -> Self {
        Wrapping(u64::from_be_bytes(input))
    }

    #[inline(always)]
    fn rotr(self, count: u32) -> Self {
        Wrapping(self.0.rotate_right(count))
    }
}

// SHA-384 and SHA-512
impl Sha2 for Wrapping<u64> {
    // FIPS 180-4 4.1.3
    const BIG_SIGMA_0: (u32, u32, u32) = (28, 34, 39);
    const BIG_SIGMA_1: (u32, u32, u32) = (14, 18, 41);
    const SMALL_SIGMA_0: (u32, u32, usize) = (1, 8, 7);
    const SMALL_SIGMA_1: (u32, u32, usize) = (19, 61, 6);

    // FIPS 180-4 4.2.3
    const K: &'static [Self] = &[
        Self(0x428a2f98d728ae22),
        Self(0x7137449123ef65cd),
        Self(0xb5c0fbcfec4d3b2f),
        Self(0xe9b5dba58189dbbc),
        Self(0x3956c25bf348b538),
        Self(0x59f111f1b605d019),
        Self(0x923f82a4af194f9b),
        Self(0xab1c5ed5da6d8118),
        Self(0xd807aa98a3030242),
        Self(0x12835b0145706fbe),
        Self(0x243185be4ee4b28c),
        Self(0x550c7dc3d5ffb4e2),
        Self(0x72be5d74f27b896f),
        Self(0x80deb1fe3b1696b1),
        Self(0x9bdc06a725c71235),
        Self(0xc19bf174cf692694),
        Self(0xe49b69c19ef14ad2),
        Self(0xefbe4786384f25e3),
        Self(0x0fc19dc68b8cd5b5),
        Self(0x240ca1cc77ac9c65),
        Self(0x2de92c6f592b0275),
        Self(0x4a7484aa6ea6e483),
        Self(0x5cb0a9dcbd41fbd4),
        Self(0x76f988da831153b5),
        Self(0x983e5152ee66dfab),
        Self(0xa831c66d2db43210),
        Self(0xb00327c898fb213f),
        Self(0xbf597fc7beef0ee4),
        Self(0xc6e00bf33da88fc2),
        Self(0xd5a79147930aa725),
        Self(0x06ca6351e003826f),
        Self(0x142929670a0e6e70),
        Self(0x27b70a8546d22ffc),
        Self(0x2e1b21385c26c926),
        Self(0x4d2c6dfc5ac42aed),
        Self(0x53380d139d95b3df),
        Self(0x650a73548baf63de),
        Self(0x766a0abb3c77b2a8),
        Self(0x81c2c92e47edaee6),
        Self(0x92722c851482353b),
        Self(0xa2bfe8a14cf10364),
        Self(0xa81a664bbc423001),
        Self(0xc24b8b70d0f89791),
        Self(0xc76c51a30654be30),
        Self(0xd192e819d6ef5218),
        Self(0xd69906245565a910),
        Self(0xf40e35855771202a),
        Self(0x106aa07032bbd1b8),
        Self(0x19a4c116b8d2d0c8),
        Self(0x1e376c085141ab53),
        Self(0x2748774cdf8eeb99),
        Self(0x34b0bcb5e19b48a8),
        Self(0x391c0cb3c5c95a63),
        Self(0x4ed8aa4ae3418acb),
        Self(0x5b9cca4f7763e373),
        Self(0x682e6ff3d6b2b8a3),
        Self(0x748f82ee5defb2fc),
        Self(0x78a5636f43172f60),
        Self(0x84c87814a1f0ab72),
        Self(0x8cc702081a6439ec),
        Self(0x90befffa23631e28),
        Self(0xa4506cebde82bde9),
        Self(0xbef9a3f7b2c67915),
        Self(0xc67178f2e372532b),
        Self(0xca273eceea26619c),
        Self(0xd186b8c721c0c207),
        Self(0xeada7dd6cde0eb1e),
        Self(0xf57d4f7fee6ed178),
        Self(0x06f067aa72176fba),
        Self(0x0a637dc5a2c898a6),
        Self(0x113f9804bef90dae),
        Self(0x1b710b35131c471b),
        Self(0x28db77f523047d84),
        Self(0x32caab7b40c72493),
        Self(0x3c9ebe0a15c9bebc),
        Self(0x431d67c49c100d4c),
        Self(0x4cc5d4becb3e42b6),
        Self(0x597f299cfc657e2a),
        Self(0x5fcb6fab3ad6faec),
        Self(0x6c44198c4a475817),
    ];
}

#[cfg(any(target_arch = "aarch64", target_arch = "arm", target_arch = "x86_64"))]
extern "C" {
    pub(super) fn GFp_sha256_block_data_order(
        state: &mut super::State,
        data: *const u8,
        num: c::size_t,
    );
    pub(super) fn GFp_sha512_block_data_order(
        state: &mut super::State,
        data: *const u8,
        num: c::size_t,
    );
}

// rust crypto vs decomposed rust crypto
#[cfg(crux)]
mod rustcrypto_rustcrypto_test {
    extern crate crucible;
    extern crate crucible_spec_macro;
    use crucible::*;
    use crucible::cryptol::munge;
    use crucible::method_spec::*;
    use crucible_spec_macro::crux_spec_for;
    use super::*;
    use super::rustcrypto_cryptol_test::*;

    #[crux_test]
    fn block_data_order_slice_equiv() {
        let state = <[u32; 8]>::symbolic("state");
        let mut state_wrap = [Wrapping(0); 8];
        wrap_slice(&state, &mut state_wrap);

        let block = <[u32; 16]>::symbolic("block");
        let mut block_wrap = [Wrapping(0); 16];
        wrap_slice(&block, &mut block_wrap);
        let mut block_bytes = [[0; 4]; 16];
        words_to_bytes(&block, &mut block_bytes);

        let output1 = block_data_order_slice::<Wrapping<u32>>(state_wrap, &[block_bytes]);
        let output2 = block_data_order_slice_words::<Wrapping<u32>>(state_wrap, &[block_wrap]);

        crucible_assert!(output1.len() == output2.len());
        for (x, y) in output1.iter().zip(output2.iter()) {
            crucible_assert!(*x == *y);
        }
    }
}

// rust crypto vs cryptol
#[cfg(crux)]
mod rustcrypto_cryptol_test {
    extern crate crucible;
    extern crate crucible_spec_macro;
    use crucible::*;
    use crucible::cryptol::munge;
    use crucible::method_spec::*;
    use crucible_spec_macro::crux_spec_for;
    use super::*;

    mod cry {
        use super::crucible::cryptol;
        cryptol! {
            path "Primitive::Keyless::Hash::SHA2::SHA256";

            pub fn message_schedule(m: [u32; 16]) -> [u32; 64]
                = "messageSchedule_Common";
            pub fn message_schedule_one(a: u32, b: u32, c: u32, d: u32) -> u32
                = r#" \a b c (d : [32]) -> d + sigma_0 c + b + sigma_1 a "#;

            pub fn compress(h: [u32; 8], w: [u32; 64]) -> [u32; 8]
                = "compress_Common";
            pub fn compress_t1(e: u32, f: u32, g: u32, h: u32, k_t: u32, w_t: u32) -> u32
                = r#" \e f g h k_t (w_t : [32]) -> h + SIGMA_1 e + Ch e f g + k_t + w_t "#;
            pub fn compress_t2(a: u32, b: u32, c: u32) -> u32
                = r#" \a b (c : [32]) -> SIGMA_0 a + Maj a b c "#;

            pub fn process_block(h: [u32; 8], m: [u32; 16]) -> [u32; 8]
                = "processBlock_Common";
        }
    }


    pub fn wrap_slice<T: Copy>(src: &[T], dest: &mut [Wrapping<T>]) {
        assert!(src.len() == dest.len());
        for (x, y) in src.iter().zip(dest.iter_mut()) {
            y.0 = *x;
        }
    }
    pub fn unwrap_slice<T: Copy>(src: &[Wrapping<T>], dest: &mut [T]) {
        assert!(src.len() == dest.len());
        for (x, y) in src.iter().zip(dest.iter_mut()) {
            *y = x.0;
        }
    }

    pub fn words_to_bytes(src: &[u32], dest: &mut [[u8; 4]]) {
        assert!(src.len() == dest.len());
        for (x, y) in src.iter().zip(dest.iter_mut()) {
            *y = x.to_be_bytes();
        }
    }


    fn cryptol_message_schedule_words(
        M: &[Wrapping<u32>; 16],
    ) -> [Wrapping<u32>; MAX_ROUNDS] {
        let mut M_raw = [0; 16];
        unwrap_slice(M, &mut M_raw);
        let W_raw = cry::message_schedule(M_raw);

        let mut W = [Wrapping(0); MAX_ROUNDS];
        wrap_slice(&W_raw, &mut W[..64]);
        W
    }

    fn cryptol_message_schedule_one(
        a: Wrapping<u32>,
        b: Wrapping<u32>,
        c: Wrapping<u32>,
        d: Wrapping<u32>,
    ) -> Wrapping<u32> {
        Wrapping(cry::message_schedule_one(a.0, b.0, c.0, d.0))
    }

    fn cryptol_compress_words(
        H: [Wrapping<u32>; 8],
        W: &[Wrapping<u32>],
    ) -> [Wrapping<u32>; 8] {
        let mut H_raw = [0; 8];
        unwrap_slice(&H, &mut H_raw);
        let mut W_raw = [0; 64];
        unwrap_slice(&W, &mut W_raw);
        let output_raw = cry::compress(H_raw, W_raw);

        let mut output = [Wrapping(0); 8];
        wrap_slice(&output_raw, &mut output);
        output
    }

    fn cryptol_compress_t1(
        e: Wrapping<u32>,
        f: Wrapping<u32>,
        g: Wrapping<u32>,
        h: Wrapping<u32>,
        k_t: Wrapping<u32>,
        w_t: Wrapping<u32>,
    ) -> Wrapping<u32> {
        Wrapping(cry::compress_t1(e.0, f.0, g.0, h.0, k_t.0, w_t.0))
    }

    fn cryptol_compress_t2(
        a: Wrapping<u32>,
        b: Wrapping<u32>,
        c: Wrapping<u32>,
    ) -> Wrapping<u32> {
        Wrapping(cry::compress_t2(a.0, b.0, c.0))
    }


    #[crux_spec_for(message_schedule_one)]
    fn message_schedule_one_equiv() {
        let [a, b, c, d] = <[Wrapping<u32>; 4]>::symbolic("input");
        let output_real = munge(message_schedule_one(a, b, c, d));
        let output_cryptol = munge(cryptol_message_schedule_one(a, b, c, d));
        crucible_assert!(output_real == output_cryptol);
    }

    #[crux_spec_for(message_schedule_words)]
    fn message_schedule_words_equiv() {
        message_schedule_one_equiv_spec().enable();

        let block = <[Wrapping<u32>; 16]>::symbolic("block");
        let output_real = munge(message_schedule_words(&block));
        let output_cryptol = munge(cryptol_message_schedule_words(&block));

        for (x, y) in output_real.iter().zip(output_cryptol.iter()) {
            crucible_assert!(*x == *y);
        }
    }

    #[crux_spec_for(compress_t1)]
    fn compress_t1_equiv() {
        let [e, f, g, h, k_t, w_t] = <[Wrapping<u32>; 6]>::symbolic("input");
        let output_real = munge(compress_t1(e, f, g, h, k_t, w_t));
        let output_cryptol = munge(cryptol_compress_t1(e, f, g, h, k_t, w_t));
        crucible_assert!(output_real == output_cryptol);
    }

    #[crux_spec_for(compress_t2)]
    fn compress_t2_equiv() {
        let [a, b, c] = <[Wrapping<u32>; 3]>::symbolic("input");
        let output_real = munge(compress_t2(a, b, c));
        let output_cryptol = munge(cryptol_compress_t2(a, b, c));
        crucible_assert!(output_real == output_cryptol);
    }

    #[crux_spec_for(compress_words)]
    fn compress_words_equiv() {
        compress_t1_equiv_spec().enable();
        compress_t2_equiv_spec().enable();

        let state = <[Wrapping<u32>; 8]>::symbolic("block");
        let schedule = <[Wrapping<u32>; 64]>::symbolic("block");
        // TODO: Remove the need for this explicit cast to `&[_]`.  Right now, removing the cast
        // and relying on implicit coercion fails with an awful error message about `tyToShapeEq:
        // type TyRef (TySlice ...) does not have representation ...` because the `crux_spec_for`
        // proc macro doesn't know to insert the cast in the `msb.add_arg(&&schedule)` call, and as
        // a result, the argument is recorded with the wrong type/repr.  I think we could work
        // around this, or at least trigger a type error in rustc with a better error message, by
        // using a wrapper function to constrain the types:
        //
        // ```Rust
        // fn dispatch<A, B, C>(msb: &mut MethodSpecBuilder, f: fn(A, B) -> C, a: A, b: B) -> C {
        //     msb.add_arg(&a);
        //     msb.add_arg(&b);
        //     // Other msb calls...
        //     C::symbolic("result")
        // }
        let output_real = munge(compress_words(state, &schedule as &[_]));
        let output_cryptol = munge(cryptol_compress_words(state, &schedule));

        for (x, y) in output_real.iter().zip(output_cryptol.iter()) {
            crucible_assert!(*x == *y);
        }
    }

    #[crux_test]
    fn block_data_order_slice_words_equiv() {
        message_schedule_words_equiv_spec().enable();
        compress_words_equiv_spec().enable();

        let state = <[u32; 8]>::symbolic("state");
        let mut state_wrap = [Wrapping(0); 8];
        wrap_slice(&state, &mut state_wrap);

        let block = <[u32; 16]>::symbolic("block");
        let mut block_wrap = [Wrapping(0); 16];
        wrap_slice(&block, &mut block_wrap);

        let output_real = munge(block_data_order_slice_words::<Wrapping<u32>>(state_wrap, &[block_wrap]));
        let output_cryptol = munge(cry::process_block(state, block));

        for (x, y) in output_real.iter().zip(output_cryptol.iter()) {
            crucible_assert!(x.0 == *y);
        }
    }
}

// rust crypto vs hacspec
#[cfg(crux)]
mod rustcrypto_hs_test {
    extern crate crucible;
    extern crate crucible_spec_macro;
    use crucible::*;
    use crucible::cryptol::munge;
    use crucible::method_spec::*;
    use crucible_spec_macro::crux_spec_for;
    use super::*;
    use hacspec_sha256 as hs;
    use hacspec_lib::prelude::*;

    const HS_K_SIZE: usize = hs::K_SIZE;

    type W32 = Wrapping<u32>;

    fn unwrap(w:W32) -> U32 { U32::from(w.0) }
    fn unwrap_slice(src: &[W32], dest: &mut [U32]) {
        assert!(src.len() == dest.len());
        for (s, d) in src.iter().zip(dest.iter_mut()) {
            *d = unwrap(*s)
        }
    }
    fn wrap(u:U32) -> W32 { Wrapping(u.0) }
    fn wrap_slice(src: &[U32], dest: &mut [W32]) {
        assert!(src.len() == dest.len());
        for (s, d) in src.iter().zip(dest.iter_mut()) {
            *d = wrap(*s)
        }
    }

    fn hs_SIGMA_0(x: U32) -> U32 { hs::sigma(x, 0, 1) }
    fn hs_SIGMA_1(x: U32) -> U32 { hs::sigma(x, 1, 1) }
    fn hs_sigma_0(x: U32) -> U32 { hs::sigma(x, 2, 0) }
    fn hs_sigma_1(x: U32) -> U32 { hs::sigma(x, 3, 0) }

    #[crux_spec_for(ch)]
    fn ch_equiv(){
        let [a, b, c] = <[W32; 3]>::symbolic("input");
        let output_real = munge(ch(a, b, c));
        let output_hs = munge(wrap(hs::ch(unwrap(a), unwrap(b), unwrap(c))));
        crucible_assert!(output_real == output_hs);
    }

    #[crux_spec_for(maj)]
    fn maj_equiv(){
        let [a, b, c] = <[W32; 3]>::symbolic("input");
        let output_real = munge(maj(a, b, c));
        let output_hs = munge(wrap(hs::maj(unwrap(a), unwrap(b), unwrap(c))));
        crucible_assert!(output_real == output_hs);
    }

    // QQQ: Could the four sigma test/theorems here be generated by a macro?

    #[crux_spec_for(SIGMA_0)]
    fn SIGMA_0_equiv(){
        let x = <W32>::symbolic("input");
        let output_real = munge(SIGMA_0(x));
        let output_hs = munge(wrap(hs_SIGMA_0(unwrap(x))));
        crucible_assert!(output_real == output_hs);
    }

    #[crux_spec_for(SIGMA_1)]
    fn SIGMA_1_equiv(){
        let x = <W32>::symbolic("input");
        let output_real = munge(SIGMA_1(x));
        let output_hs = munge(wrap(hs_SIGMA_1(unwrap(x))));
        crucible_assert!(output_real == output_hs);
    }

    #[crux_spec_for(sigma_0)]
    fn sigma_0_equiv(){
        let x = <W32>::symbolic("input");
        let output_real = munge(sigma_0(x));
        let output_hs = munge(wrap(hs_sigma_0(unwrap(x))));
        crucible_assert!(output_real == output_hs);
    }

    #[crux_spec_for(sigma_1)]
    fn sigma_1_equiv(){
        let x = <W32>::symbolic("input");
        let output_real = munge(sigma_1(x));
        let output_hs = munge(wrap(hs_sigma_1(unwrap(x))));
        crucible_assert!(output_real == output_hs);
    }

    #[crux_spec_for(compress_t1)]
    fn compress_t1_equiv() {
        let hs_compress_t1 = |e, f, g, h, k_t, w_t| h + hs_SIGMA_1(e) + hs::ch(e, f, g) + k_t + w_t;
        SIGMA_1_equiv_spec().enable();
        ch_equiv_spec().enable();
        let [e, f, g, h, k_t, w_t] = <[W32; 6]>::symbolic("input");
        let output_real = munge(compress_t1(e, f, g, h, k_t, w_t));
        let output_hs = munge(wrap(hs_compress_t1(unwrap(e), unwrap(f), unwrap(g), unwrap(h), unwrap(k_t), unwrap(w_t))));
        crucible_assert!(output_real == output_hs);
    }

    #[crux_spec_for(compress_t2)]
    fn compress_t2_equiv() {
        let hs_compress_t2 = |a, b, c| hs_SIGMA_0(a) + hs::maj(a, b, c);
        SIGMA_0_equiv_spec().enable();
        maj_equiv_spec().enable();
        let [a, b, c] = <[W32; 3]>::symbolic("input");
        let output_real = munge(compress_t2(a, b, c));
        let output_hs = munge(wrap(hs_compress_t2(unwrap(a), unwrap(b), unwrap(c))));
        crucible_assert!(output_real == output_hs);
    }

    #[crux_spec_for(compress_words)]
    fn compress_words_equiv() {
        fn hs_compress_words(
            Hw: [W32; CHAINING_WORDS],
            Ww: &[W32]
        ) -> [W32; CHAINING_WORDS] {
            // convert implementation's inputs to spec's inputs
            let mut Hu = [U32(0); CHAINING_WORDS];
            let mut Wu = [U32(0); HS_K_SIZE];
            unwrap_slice(&Hw, &mut Hu);
            unwrap_slice(&Ww, &mut Wu);
            // run spec function
            let hs::Hash(mut output_Hu) = hs::shuffle(hs::RoundConstantsTable(Wu), hs::Hash(Hu));
            // match the behavior of the implementation (the spec does this `+` in hs::compress)
            for i in 0..8 {
                output_Hu[i] = output_Hu[i] + Hu[i];
            }
            // convert spec's output to implementation's output
            let mut output_Hw = [Wrapping(0); CHAINING_WORDS];
            wrap_slice(&output_Hu, &mut output_Hw);
            output_Hw
        }
        compress_t1_equiv_spec().enable();
        compress_t2_equiv_spec().enable();
        let state = <[W32; CHAINING_WORDS]>::symbolic("state");
        let schedule = <[W32; HS_K_SIZE]>::symbolic("schedule");
        // TODO: Remove the need for this explicit cast to `&[_]`.  Right now, removing the cast
        // and relying on implicit coercion fails with an awful error message about `tyToShapeEq:
        // type TyRef (TySlice ...) does not have representation ...` because the `crux_spec_for`
        // proc macro doesn't know to insert the cast in the `msb.add_arg(&&schedule)` call, and as
        // a result, the argument is recorded with the wrong type/repr.  I think we could work
        // around this, or at least trigger a type error in rustc with a better error message, by
        // using a wrapper function to constrain the types:
        //
        // ```Rust
        // fn dispatch<A, B, C>(msb: &mut MethodSpecBuilder, f: fn(A, B) -> C, a: A, b: B) -> C {
        //     msb.add_arg(&a);
        //     msb.add_arg(&b);
        //     // Other msb calls...
        //     C::symbolic("result")
        // }
        let output_real = munge(compress_words(state, &schedule as &[_]));
        let output_hs = munge(hs_compress_words(state, &schedule));
        crucible_assert!(output_real.len() == output_hs.len());
        for (real, hs) in output_real.iter().zip(output_hs.iter()) {
            crucible_assert!(*real == *hs);
        }
    }

    #[crux_spec_for(message_schedule_one)]
    fn message_schedule_one_equiv() {
        let hs_message_schedule_one = |a, b, c, d| hs_sigma_1(a) + b + hs_sigma_0(c) + d;
        sigma_0_equiv_spec().enable();
        sigma_1_equiv_spec().enable();
        let [a, b, c, d] = <[W32; 4]>::symbolic("input");
        let output_real = munge(message_schedule_one(a, b, c, d));
        let output_hs = munge(wrap(hs_message_schedule_one(unwrap(a), unwrap(b), unwrap(c), unwrap(d))));
        crucible_assert!(output_real == output_hs);
    }

    #[crux_spec_for(message_schedule_words)]
    fn message_schedule_words_equiv() {
        fn U32_to_be_bytes(ints: &[U32]) -> Vec<U8> {
            U32::to_le_bytes(ints).iter().rev().map(|x| *x).collect()
        }
        fn U32_from_be_bytes(bytes: &[U8]) -> Vec<U32> {
            let v = bytes.iter().rev().map(|x| *x).collect::<Vec<_>>();
            U32::from_le_bytes(&v[..])
        }
        override_(U32::to_be_bytes, U32_to_be_bytes);
        override_(U32::from_be_bytes, U32_from_be_bytes);

        fn hs_message_schedule_words(
            Mw: &[W32; 16],
        ) -> [W32; MAX_ROUNDS] {
            // convert implementation's inputs to spec's inputs
            let mut Mb = [U8(0); 64];
            Mw.iter()
                .flat_map(|w| unwrap(*w).to_be_bytes().native_slice().to_vec())
                .enumerate().for_each(|(i, b): (usize, U8)| Mb[i] = b);
            // run spec function
            let hs::RoundConstantsTable(output_Wu) = hs::schedule(hs::Block(Mb)); // :: [u8;64=BLOCK_SIZE] 512b → [U32;64=K_SIZE]
            // convert spec's output to implementation's output
            let mut output_Ww = [Wrapping(0); MAX_ROUNDS];
            wrap_slice(&output_Wu, &mut output_Ww[..HS_K_SIZE]); // NOTE: the implementation leaves 64..80 zeros
            output_Ww
        }
        message_schedule_one_equiv_spec().enable();
        let block = <[W32; 16]>::symbolic("block");
        let output_real = munge(message_schedule_words(&block)); // :: [W32;16] 512b → [W32;80=MAX_ROUNDS] but 64..80 are zeros
        let output_hs = munge(hs_message_schedule_words(&block));
        crucible_assert!(output_real.len() == output_hs.len());
        for (real, hs) in output_real.iter().zip(output_hs.iter()) {
            crucible_assert!(*real == *hs);
        }
    }

    #[crux_spec_for(block_data_order_slice_words)]
    fn block_data_order_slice_words_equiv() {
        fn hs_block_data_order_slice_words(
            mut Hw: [W32; CHAINING_WORDS],
            Mw: &[[W32; 16]],
        ) -> [W32; CHAINING_WORDS] {
            // convert implementation's inputs to spec's inputs
            let mut Hu = [U32(0); CHAINING_WORDS];
            unwrap_slice(&Hw, &mut Hu[..]);
            let mut Mb = [U8(0); 64];
            Mw[0].iter()
                .flat_map(|w| unwrap(*w).to_be_bytes().native_slice().to_vec())
                .enumerate().for_each(|(i, b): (usize, U8)| Mb[i] = b);
            // run spec function
            let hs::Hash(output_Hu) = hs::compress(hs::Block(Mb), hs::Hash(Hu));
            // convert spec's output to implementation's output
            let mut output_Hw = [Wrapping(0); CHAINING_WORDS];
            wrap_slice(&output_Hu, &mut output_Hw);
            output_Hw
        }
        message_schedule_words_equiv_spec().enable();
        compress_words_equiv_spec().enable();
        let state = <[W32; 8]>::symbolic("state");
        let block = <[W32; 16]>::symbolic("block");
        let output_real = munge(block_data_order_slice_words(state, &[block]));
        let output_hs = munge(hs_block_data_order_slice_words(state, &[block]));
        crucible_assert!(output_real.len() == output_hs.len());
        for (real, hs) in output_real.iter().zip(output_hs.iter()) {
            crucible_assert!(*real == *hs);
        }
    }
}
