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
        let (a, b, c, d, e) = step3(a, b, c, d, e, W[ 0..20].try_into().unwrap(), Wrapping(0x5a827999), ch);
        let (a, b, c, d, e) = step3(a, b, c, d, e, W[20..40].try_into().unwrap(), Wrapping(0x6ed9eba1), parity);
        let (a, b, c, d, e) = step3(a, b, c, d, e, W[40..60].try_into().unwrap(), Wrapping(0x8f1bbcdc), maj);
        let (a, b, c, d, e) = step3(a, b, c, d, e, W[60..80].try_into().unwrap(), Wrapping(0xca62c1d6), parity);

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

#[inline(always)]
fn rotl(x: W32, n: u32) -> W32 {
    Wrapping(x.0.rotate_left(n))
}

fn myrotl(x: u32, n: u32) -> u32 {
    x.rotate_left(n)
}

#[cfg(crux)]
mod crux_test {
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
            path "Primitive::Keyless::Hash::SHA1";

            pub fn process_block(h: [u32; 5], m: [u32; 16]) -> [u32; 8]
                = "block";

            pub fn rotl(a: u32, n: u32) -> u32
                = r#" \a n -> (a <<< n)"#;

            pub fn parity(a: u32, b: u32, c: u32) -> u32
                = r#"\a b c -> (a ^ b ^ c)"#;
        }
    }

    fn wrap_slice<T: Copy>(src: &[T], dest: &mut [Wrapping<T>]) {
        assert!(src.len() == dest.len());
        for (x, y) in src.iter().zip(dest.iter_mut()) {
            y.0 = *x;
        }
    }

    // fn cryptol_rotl(
    //     a: W32,
    //     n: W32
    // ) -> W32 {
    //     Wrapping(cry::rotl(a, n))
    // }

    fn cryptol_parity(
        a: W32,
        b: W32,
        c: W32
    ) -> W32 {
        Wrapping(cry::parity(a.0, b.0, c.0))
    }

    #[crux_spec_for(parity)]
    fn parity_equiv(){
        let [a, b, c] = <[W32; 3]>::symbolic("input");
        let output_real = munge(parity(a, b, c));
        let output_cryptol = munge(cryptol_parity(a, b, c));
        crucible_assert!(output_real == output_cryptol);
    }

    #[crux_test]
    fn rotl_equiv(){
        let a =<u32>::symbolic("a");
        let n = <u32>::symbolic("n");
        let output_real = munge(myrotl(a, n));
        let output_cryptol = munge(cry::rotl(a, n));
        crucible_assert!(output_real == output_cryptol);
    }

    #[crux_test]
    fn block_data_order_equiv() {
        parity_equiv_spec().enable();
        //rotl_equiv_spec().enable();

        let state = <[u32; 5]>::symbolic("block");
        let mut state_wrap = [Wrapping(0); 5];
        wrap_slice(&state, &mut state_wrap);

        let mut block = <[u32; 16]>::symbolic("block");
        let mut block_wrap = [Wrapping(0); 16];
        wrap_slice(&block, &mut block_wrap);

        let mut block_split_byte_array = [[0u8; 4]; 16];
        let output_real = munge(block_data_order_(state_wrap, &[block_split_byte_array]));
        let output_cryptol = munge(cry::process_block(state, block));

        for (x, y) in output_real.iter().zip(output_cryptol.iter()) {
            crucible_assert!(x.0 == *y);
        }
    }






}