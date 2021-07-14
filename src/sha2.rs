
use std::convert::TryInto;

pub fn sha256(message: &str) -> [u32; 8] {
    let mut h = H0_SHA256.clone();
    for chunk in chunkify(message.to_string()) {
        let mut w = chunk.to_vec();
        for t in 16..64 {
            w.push(lil_sig_1(w[t - 2])
                .wrapping_add(w[t - 7])
                .wrapping_add(lil_sig_0(w[t - 15]))
                .wrapping_add(w[t - 16]));
        }
        let mut vars = h.clone();
        for t in 0..64 {
            let t1 = vars[7]
                .wrapping_add(big_sig_1(vars[4]))
                .wrapping_add(ch(vars[4], vars[5], vars[6]))
                .wrapping_add(K[t])
                .wrapping_add(w[t]);

            let t2 = big_sig_0(vars[0]).wrapping_add(maj(vars[0], vars[1], vars[2]));
            for i in (0..8).rev() {
                vars[i] =  match i {
                    4 => vars[3].wrapping_add(t1),
                    0 => t1.wrapping_add(t2),
                    _ => vars[i - 1]
                };
            }
        }
        for i in 0..8 {
            h[i] = h[i].wrapping_add(vars[i]);
        }
    }
    h
}

fn bytes_to_words(bytes: &[u8]) -> [u32; 16] {
    let bytes: [u8; 64] = bytes.try_into().expect("bytes should have length 64");
    let words = bytes.chunks_exact(4);
    let mut ans = [0; 16];
    for (i, word) in words.enumerate() {
        let arr: [u8; 4] = word.try_into().unwrap();
        ans[i] = u32::from_be_bytes(arr);
    }
    ans
}

fn chunkify(message: String) -> Vec<[u32; 16]> {
    let mut bytes = message.into_bytes();
    let l = bytes.len();
    bytes.push(1u8 << 7);
    let mut last_l = (l + 1) % 64;
    if last_l > 56 {
        for _ in 0..64 - last_l { bytes.push(0u8); }
        last_l = 0;
    }
    for _ in 0..56 - last_l { bytes.push(0u8); }
    for &byte in &(l * 8).to_be_bytes() { bytes.push(byte); }

    bytes.chunks(64).map(|x| bytes_to_words(x)).collect()
}

fn rot_r (mut x: u32, n: u32) -> u32 {
    let a = x << (32 - n);
    x >>= n;
    a | x
} 

/*
fn rot_l (mut x: u32, n: u32) -> u32 {
    let a = x >> (32 - n);
    x <<= n;
    a | x
}
*/

fn big_sig_0(x: u32) -> u32 {
    rot_r(x, 2) ^ rot_r(x, 13) ^ rot_r(x, 22)
}

fn big_sig_1(x: u32) -> u32 {
    rot_r(x, 6) ^ rot_r(x, 11) ^ rot_r(x, 25)
}

fn lil_sig_0(x: u32) -> u32 {
    rot_r(x, 7) ^ rot_r(x, 18) ^ (x >> 3)
}

fn lil_sig_1(x: u32) -> u32 {
    rot_r(x, 17) ^ rot_r(x, 19) ^ (x >> 10)
}

fn ch(x: u32, y: u32, z: u32) -> u32 {
    (x & y) ^ (!x & z)
}

fn maj(x: u32, y: u32, z: u32) -> u32 {
    (x & y) ^ (x & z) ^ (y & z)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run_test_case(message: &str, hash: &str) {
        let parsed: Vec<u32> = hash.split(' ').map(|x| u32::from_str_radix(x, 16).unwrap()).collect();
        assert_eq!(parsed, sha256(message));
    }
    #[test]
    fn simple_test() {
        let hash = "BA7816BF 8F01CFEA 414140DE 5DAE2223 B00361A3 96177A9C B410FF61 F20015AD";
        run_test_case("abc", hash);
     }

 #[test]
    fn long_test() {
        let message = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
        let hash = "248D6A61 D20638B8 E5C02693 0C3E6039 A33CE459 64FF2167 F6ECEDD4 19DB06C1";
        run_test_case(message, hash);
    }
}

const H0_SHA256: [u32; 8] = [
    0x6a09e667,
    0xbb67ae85,
    0x3c6ef372,
    0xa54ff53a,
    0x510e527f,
    0x9b05688c,
    0x1f83d9ab,
    0x5be0cd19,
];

const K: [u32; 64] = [
    0x428a2f98,
    0x71374491,
    0xb5c0fbcf,
    0xe9b5dba5,
    0x3956c25b,
    0x59f111f1,
    0x923f82a4,
    0xab1c5ed5,
    0xd807aa98,
    0x12835b01,
    0x243185be,
    0x550c7dc3,
    0x72be5d74,
    0x80deb1fe,
    0x9bdc06a7,
    0xc19bf174,
    0xe49b69c1,
    0xefbe4786,
    0x0fc19dc6,
    0x240ca1cc,
    0x2de92c6f,
    0x4a7484aa,
    0x5cb0a9dc,
    0x76f988da,
    0x983e5152,
    0xa831c66d,
    0xb00327c8,
    0xbf597fc7,
    0xc6e00bf3,
    0xd5a79147,
    0x06ca6351,
    0x14292967,
    0x27b70a85,
    0x2e1b2138,
    0x4d2c6dfc,
    0x53380d13,
    0x650a7354,
    0x766a0abb,
    0x81c2c92e,
    0x92722c85,
    0xa2bfe8a1,
    0xa81a664b,
    0xc24b8b70,
    0xc76c51a3,
    0xd192e819,
    0xd6990624,
    0xf40e3585,
    0x106aa070,
    0x19a4c116,
    0x1e376c08,
    0x2748774c,
    0x34b0bcb5,
    0x391c0cb3,
    0x4ed8aa4a,
    0x5b9cca4f,
    0x682e6ff3,
    0x748f82ee,
    0x78a5636f,
    0x84c87814,
    0x8cc70208,
    0x90befffa,
    0xa4506ceb,
    0xbef9a3f7,
    0xc67178f2,
];
