use chacha20::ChaCha20;
// Import relevant traits
use chacha20::cipher::{KeyIvInit, StreamCipher, StreamCipherSeek};
use hex_literal::hex;

fn main() {
    let key = hex!("00 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f 10 11 12 13 14 15 16 17 18 19 1a 1b 1c 1d 1e 1f");
    let nonce = hex!("00 00 00 00 00 00 00 4a 00 00 00 00");

    let mut buffer = "Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.".as_bytes().to_vec();

    let mut cipher = ChaCha20::new(&key.into(), &nonce.into());
    
    let mut prefix = [0u8; 64];
    cipher.apply_keystream(&mut prefix);

    cipher.apply_keystream(&mut buffer);

    println!("{:x?}", buffer);
}
