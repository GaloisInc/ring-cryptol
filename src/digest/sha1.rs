// Copyright 2015-2016 Brian Smith.
// Copyright 2016 Simon Sapin.
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

use super::sha2::{ch, maj, Word};
use crate::c;
use core::{convert::TryInto, num::Wrapping};

pub const BLOCK_LEN: usize = 512 / 8;
pub const CHAINING_LEN: usize = 160 / 8;
pub const OUTPUT_LEN: usize = 160 / 8;
const CHAINING_WORDS: usize = CHAINING_LEN / 4;

type W32 = Wrapping<u32>;

// FIPS 180-4 4.1.1
#[inline]
fn parity(x: W32, y: W32, z: W32) -> W32 {
    x ^ y ^ z
}

type State = [W32; CHAINING_WORDS];
const ROUNDS: usize = 80;

pub(super) extern "C" fn block_data_order(
    state: &mut super::State,
    data: *const u8,
    num: c::size_t,
) {
    let state = unsafe { &mut state.as32 };
    let state: &mut State = (&mut state[..CHAINING_WORDS]).try_into().unwrap();
    let data = data as *const [<W32 as Word>::InputBytes; 16];
    let blocks = unsafe { core::slice::from_raw_parts(data, num) };
    *state = block_data_order_(*state, blocks)
}

#[inline]
#[rustfmt::skip]
fn block_data_order_(mut H: State, M: &[[<W32 as Word>::InputBytes; 16]]) -> State {
    for M in M {
        // FIPS 180-4 6.1.2 Step 1
        let mut W: [W32; ROUNDS] = [W32::ZERO; ROUNDS];
        for t in 0..16 {
            W[t] = W32::from_be_bytes(M[t]);
        }
        for t in 16..ROUNDS {
            let wt = W[t - 3] ^ W[t - 8] ^ W[t - 14] ^ W[t - 16];
            W[t] = rotl(wt, 1);
        }

        // FIPS 180-4 6.1.2 Step 2
        let a = H[0];
        let b = H[1];
        let c = H[2];
        let d = H[3];
        let e = H[4];

        // FIPS 180-4 6.1.2 Step 3 with constants and functions from FIPS 180-4 {4.1.1, 4.2.1}
        let (a, b, c, d, e) = step3_ch(a, b, c, d, e, W[ 0..20].try_into().unwrap());
        let (a, b, c, d, e) = step3_parity1(a, b, c, d, e, W[20..40].try_into().unwrap());
        let (a, b, c, d, e) = step3_maj(a, b, c, d, e, W[40..60].try_into().unwrap());
        let (a, b, c, d, e) = step3_parity2(a, b, c, d, e, W[60..80].try_into().unwrap());

        // FIPS 180-4 6.1.2 Step 4
        H[0] += a;
        H[1] += b;
        H[2] += c;
        H[3] += d;
        H[4] += e;
    }

    H
}

#[inline(always)]
fn step3_ch(
    mut a: W32,
    mut b: W32,
    mut c: W32,
    mut d: W32,
    mut e: W32,
    W: [W32; 20],
) -> (W32, W32, W32, W32, W32) {
    let k = Wrapping(0x5a827999);
    for W_t in W.iter() {
        let T = rotl(a, 5) + ch(b, c, d) + e + k + W_t;
        e = d;
        d = c;
        c = rotl(b, 30);
        b = a;
        a = T;
    }
    (a, b, c, d, e)
}

#[inline(always)]
fn step3_parity1(
    mut a: W32,
    mut b: W32,
    mut c: W32,
    mut d: W32,
    mut e: W32,
    W: [W32; 20],
) -> (W32, W32, W32, W32, W32) {
    let k = Wrapping(0x6ed9eba1);
    for W_t in W.iter() {
        let T = rotl(a, 5) + parity(b, c, d) + e + k + W_t;
        e = d;
        d = c;
        c = rotl(b, 30);
        b = a;
        a = T;
    }
    (a, b, c, d, e)
}

#[inline(always)]
fn step3_parity2(
    mut a: W32,
    mut b: W32,
    mut c: W32,
    mut d: W32,
    mut e: W32,
    W: [W32; 20],
) -> (W32, W32, W32, W32, W32) {
    let k = Wrapping(0xca62c1d6);
    for W_t in W.iter() {
        let T = rotl(a, 5) + parity(b, c, d) + e + k + W_t;
        e = d;
        d = c;
        c = rotl(b, 30);
        b = a;
        a = T;
    }
    (a, b, c, d, e)
}

#[inline(always)]
fn step3_maj(
    mut a: W32,
    mut b: W32,
    mut c: W32,
    mut d: W32,
    mut e: W32,
    W: [W32; 20],
) -> (W32, W32, W32, W32, W32) {
    let k = Wrapping(0x8f1bbcdc);
    for W_t in W.iter() {
        let T = rotl(a, 5) + maj(b, c, d) + e + k + W_t;
        e = d;
        d = c;
        c = rotl(b, 30);
        b = a;
        a = T;
    }
    (a, b, c, d, e)
}

#[inline(always)]
fn step3(
    mut a: W32,
    mut b: W32,
    mut c: W32,
    mut d: W32,
    mut e: W32,
    W: [W32; 20],
    k: W32,
    f: impl Fn(W32, W32, W32) -> W32,
) -> (W32, W32, W32, W32, W32) {
    for W_t in W.iter() {
        let T = rotl(a, 5) + f(b, c, d) + e + k + W_t;
        e = d;
        d = c;
        c = rotl(b, 30);
        b = a;
        a = T;
    }
    (a, b, c, d, e)
}

fn cryptol_step3(
    mut a: W32,
    mut b: W32,
    mut c: W32,
    mut d: W32,
    mut e: W32,
    W: [W32; 20],
    k: W32,
    f: impl Fn(W32, W32, W32) -> W32,
) -> (W32, W32, W32, W32, W32) {
    for W_t in W.iter() {
        let T = rotl(a, 5) + f(b, c, d) + e + k + W_t;
        e = d;
        d = c;
        c = rotl(b, 30);
        b = a;
        a = T;
    }
    (a, b, c, d, e)
}


#[inline(always)]
fn rotl(x: W32, n: u32) -> W32 {
    Wrapping(x.0.rotate_left(n))
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

pub mod cry{
    extern crate crucible;
    use crucible::*;
    // use super::crucible::cryptol;
    pub type btype = ([u32; 5], [u32; 16]);
    cryptol! {
        path "Primitive::Keyless::Hash::SHA1";

        pub fn process_block(hm: btype) -> [u32; 5]
            = "block";

        pub fn rotl(a: u32, n: u32) -> u32
            = r#" \(a: [32]) (n: [32]) -> (a <<< n)"#;

        pub fn parity(a: u32, b: u32, c: u32) -> u32
            = r#"\(a: [32]) (b: [32]) (c: [32]) -> (a ^ b ^ c)"#;

        pub fn ch(x: u32, y: u32, z: u32) -> u32
            = r#"\(x: [32]) (y: [32]) (z: [32]) -> (x && y) || (~x && z)"#;

        pub fn maj(x: u32, y: u32, z: u32) -> u32
            = "maj";
            //r#"\(x: [32]) (y: [32]) (z: [32]) -> (x && y) || (x && z) || (y && z)"#;


    }
}

// Of course, CRYPTOLPATH need to get updated by adding path to the current directory
pub mod step {
    extern crate crucible;
    use crucible::*;
    pub type step3_type = (u32, u32, u32, u32, u32, [u32; 20]);

    cryptol! {
        path "step3";
        pub fn step3_ch (arg: step3_type) -> (u32, u32, u32, u32, u32)
            = "step3_ch";

        pub fn step3_maj (arg: step3_type) -> (u32, u32, u32, u32, u32)
            = "step3_maj";

        pub fn step3_parity1 (arg: step3_type) -> (u32, u32, u32, u32, u32)
            = "step3_parity1";

        pub fn step3_parity2 (arg: step3_type) -> (u32, u32, u32, u32, u32)
            = "step3_parity2";
    }
}

//     use rand::Rng;
//     #[test]
//     fn step3_ch_eq(){
//         let mut rng = rand.thread_rng();
//         let [a, b, c, d, e] = rng.gen::<[u32; 5]>();
//         let w = rng.gen::<[u32; 20]>();
//         let output_real = step3_ch(a, b, c, d, e, w);
//         let output_cryptol = cryptol_step3_ch(Wrapping(a), Wrapping(b), Wrapping(c), Wrapping(d),
//         Wrapping(e), w.iter().map(|x| Wrapping(x)).collect());
//         assert_eq!(output_real, output_cryptol);
// }

    fn wrap_slice<T: Copy>(src: &[T], dest: &mut [Wrapping<T>]) {
        assert!(src.len() == dest.len());
        for (x, y) in src.iter().zip(dest.iter_mut()) {
            y.0 = *x;
        }
    }

    fn cryptol_rotl(
        a: W32,
        n: u32
    ) -> W32 {
        Wrapping(cry::rotl(a.0, n))
    }

    fn cryptol_parity(
        a: W32,
        b: W32,
        c: W32
    ) -> W32 {
        Wrapping(cry::parity(a.0, b.0, c.0))
    }

    fn cryptol_ch(
        a: W32,
        b: W32,
        c: W32
    ) -> W32 {
        Wrapping(cry::ch(a.0, b.0, c.0))
    }

    fn cryptol_maj(
        a: W32,
        b: W32,
        c: W32
    ) -> W32 {
        Wrapping(cry::maj(a.0, b.0, c.0))
    }

    #[inline(always)]
    fn cryptol_step3_ch(
    mut a: W32,
    mut b: W32,
    mut c: W32,
    mut d: W32,
    mut e: W32,
    W: [W32; 20],
    ) -> (W32, W32, W32, W32, W32) {
    let mut ws = [0u32; 20];
    for i in 0..20 {
        ws[i] = W[i].0;
    }
    let res = step::step3_ch((a.0, b.0, c.0, d.0, e.0, ws));
    (Wrapping(res.0), Wrapping(res.1), Wrapping(res.2), Wrapping(res.3), Wrapping(res.4))
    }

    #[inline(always)]
    fn cryptol_step3_maj(
    mut a: W32,
    mut b: W32,
    mut c: W32,
    mut d: W32,
    mut e: W32,
    W: [W32; 20],
    ) -> (W32, W32, W32, W32, W32) {
    let mut ws = [0u32; 20];
    for i in 0..20 {
        ws[i] = W[i].0;
    }
    let res = step::step3_maj((a.0, b.0, c.0, d.0, e.0, ws));
    (Wrapping(res.0), Wrapping(res.1), Wrapping(res.2), Wrapping(res.3), Wrapping(res.4))
    }

    #[inline(always)]
    fn cryptol_step3_parity1(
    mut a: W32,
    mut b: W32,
    mut c: W32,
    mut d: W32,
    mut e: W32,
    W: [W32; 20],
    ) -> (W32, W32, W32, W32, W32) {
    let mut ws = [0u32; 20];
    for i in 0..20 {
        ws[i] = W[i].0;
    }
    let res = step::step3_parity1((a.0, b.0, c.0, d.0, e.0, ws));
    (Wrapping(res.0), Wrapping(res.1), Wrapping(res.2), Wrapping(res.3), Wrapping(res.4))
    }

    #[inline(always)]
    fn cryptol_step3_parity2(
    mut a: W32,
    mut b: W32,
    mut c: W32,
    mut d: W32,
    mut e: W32,
    W: [W32; 20],
    ) -> (W32, W32, W32, W32, W32) {
    let mut ws = [0u32; 20];
    for i in 0..20 {
        ws[i] = W[i].0;
    }
    let res = step::step3_parity2((a.0, b.0, c.0, d.0, e.0, ws));
    (Wrapping(res.0), Wrapping(res.1), Wrapping(res.2), Wrapping(res.3), Wrapping(res.4))
    }

   // proved
    #[crux_spec_for(ch)]
    fn ch_equiv(){
        let [a, b, c] = <[W32; 3]>::symbolic("input");
        let output_real = munge(ch(a, b, c));
        let output_cryptol = munge(cryptol_ch(a, b, c));
        crucible_assert!(output_real == output_cryptol);
    }

    // proved
    #[crux_spec_for(maj)]
    fn maj_equiv(){
        let [a, b, c] = <[W32; 3]>::symbolic("input");
        let output_real = munge(maj(a, b, c));
        let output_cryptol = munge(cryptol_maj(a, b, c));
        crucible_assert!(output_real == output_cryptol);
    }

    // proved
    #[crux_spec_for(parity)]
    fn parity_equiv(){
        let [a, b, c] = <[W32; 3]>::symbolic("input");
        let output_real = munge(parity(a, b, c));
        let output_cryptol = munge(cryptol_parity(a, b, c));
        crucible_assert!(output_real == output_cryptol);
    }

    // proved
    #[crux_spec_for(rotl)]
    fn rotl_equiv(){
        let a =<W32>::symbolic("a");
        let n = <u32>::symbolic("n");
        let output_real = munge(rotl(a, n));
        let output_cryptol = munge(cryptol_rotl(a, n));
        crucible_assert!(output_real == output_cryptol);
    }

    // proved
    #[crux_spec_for(step3_ch)]
    fn step3_ch_equiv(){
        rotl_equiv_spec().enable();
        ch_equiv_spec().enable();
        let [a, b, c, d, e] = <[W32; 5]>::symbolic("input");
        let w = <[W32; 20]>::symbolic("ws");
        let output_real = munge(step3_ch(a, b, c, d, e, w));
        let output_cryptol = munge(cryptol_step3_ch(a, b, c, d, e, w));
        // // crucible_assert!(x + y == z, "bad arithmetic: {} + {} != {}", x, y, z)
        // crucible_assert!(false, "bad arithmetic: {} + {} != {}", 3, 4, 5);
        // // crucible_assert!(false, "output_real = {:?}, output_cryptol ={:?}", output_real, output_cryptol);
        crucible_assert!(output_real == output_cryptol);
    }

    // proved
    #[crux_spec_for(step3_maj)]
    fn step3_maj_equiv(){
        rotl_equiv_spec().enable();
        maj_equiv_spec().enable();
        let [a, b, c, d, e] = <[W32; 5]>::symbolic("input");
        let w = <[W32; 20]>::symbolic("ws");
        let output_real = munge(step3_maj(a, b, c, d, e, w));
        let output_cryptol = munge(cryptol_step3_maj(a, b, c, d, e, w));
        crucible_assert!(output_real == output_cryptol);
    }

    // proved
    #[crux_spec_for(step3_parity1)]
    fn step3_parity1_equiv(){
        rotl_equiv_spec().enable();
        parity_equiv_spec().enable();
        let [a, b, c, d, e] = <[W32; 5]>::symbolic("input");
        let mut w = <[u32; 20]>::symbolic("ws");
        let mut w_wrap = [Wrapping(0); 20];
        let output_real = munge(step3_parity1(a, b, c, d, e, w_wrap));
        let output_cryptol = munge(cryptol_step3_parity1(a, b, c, d, e, w_wrap));
        crucible_assert!(output_real == output_cryptol);
    }

    // proved
    #[crux_spec_for(step3_parity2)]
    fn step3_parity2_equiv(){
        rotl_equiv_spec().enable();
        parity_equiv_spec().enable();
        let [a, b, c, d, e] = <[W32; 5]>::symbolic("input");
        let w = <[W32; 20]>::symbolic("ws");
        let output_real = munge(step3_parity2(a, b, c, d, e, w));
        let output_cryptol = munge(cryptol_step3_parity2(a, b, c, d, e, w));
        crucible_assert!(output_real == output_cryptol);
    }

    // taking time to terminate
    #[crux_test]
    fn block_data_order_equiv() {
        parity_equiv_spec().enable();
        rotl_equiv_spec().enable();
        ch_equiv_spec().enable();
        maj_equiv_spec().enable();
        // step3_ch_equiv_spec().enable();
        // step3_maj_equiv_spec().enable();
        // step3_parity1_equiv_spec().enable();
        // step3_parity2_equiv_spec().enable();
        override_(step3_ch, cryptol_step3_ch);
        override_(step3_maj, cryptol_step3_maj);
        override_(step3_parity1, cryptol_step3_parity1);
        override_(step3_parity2, cryptol_step3_parity2);

        let state = <[u32; 5]>::symbolic("state");
        let mut state_wrap = [Wrapping(0); 5];
        wrap_slice(&state, &mut state_wrap);

        let mut block = <[u32; 16]>::symbolic("block");
        let mut block_wrap = [Wrapping(0); 16];
        wrap_slice(&block, &mut block_wrap);

        let mut block_split_byte_array = [[0u8; 4]; 16];
        let output_real = block_data_order_(state_wrap, &[block_split_byte_array]);
        let output_cryptol = cry::process_block((state, block));

        for (x, y) in output_real.iter().zip(output_cryptol.iter()) {
            crucible_assert!(x.0 == *y);
        }
    }
}

// rust crypto vs hacspec
#[cfg(crux)]
mod rustcrypto_hs_test {
}
