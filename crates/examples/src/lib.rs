use aes::Aes128;
use cipher::{BlockEncrypt, KeyInit, generic_array::GenericArray};
use js_sys::{Uint8Array, Array, Object};
use serde::Serialize;
use wasm_bindgen::prelude::*;

use std::collections::{HashMap, HashSet};

const AES128_BLOCK_SIZE: usize = 16;

/// Small serializable structure returned to JS.
#[derive(Serialize)]
pub struct DemoResult {
    ciphertext: Vec<u8>,
    recovered: Vec<u8>,
    steps: Vec<String>,
}

/// Convert Uint8Array -> Vec<u8>
fn u8array_to_vec(arr: &Uint8Array) -> Vec<u8> {
    let mut v = vec![0u8; arr.length() as usize];
    arr.copy_to(&mut v[..]);
    v
}

fn vec_to_js_array(v: Vec<String>) -> Array {
    v.into_iter().map(JsValue::from).collect()
}

/// PKCS#7 pad producing a new Vec
fn pkcs7_pad_vec(input: &[u8], block_size: usize) -> Vec<u8> {
    let mut v = input.to_vec();
    let pad = block_size - (v.len() % block_size);
    v.extend(std::iter::repeat(pad as u8).take(pad));
    v
}

/// AES-128-ECB encrypt with PKCS#7 padding (manual ECB)
fn aes128_ecb_encrypt(key: &[u8; 16], plaintext: &[u8]) -> Vec<u8> {
    let mut pt = pkcs7_pad_vec(plaintext, AES128_BLOCK_SIZE);
    let cipher = Aes128::new(GenericArray::from_slice(key));
    let mut out = Vec::with_capacity(pt.len());
    for chunk in pt.chunks_exact(AES128_BLOCK_SIZE) {
        let mut block = GenericArray::clone_from_slice(chunk);
        cipher.encrypt_block(&mut block);
        out.extend_from_slice(&block);
    }
    out
}

/// Oracle used in the demo: encrypt(attacker_input || unknown_suffix)
struct Oracle {
    key: [u8; 16],
    unknown_suffix: Vec<u8>,
}

impl Oracle {
    fn new(key: [u8; 16], unknown_suffix: Vec<u8>) -> Self {
        Self { key, unknown_suffix }
    }

    fn encrypt(&self, attacker_input: &[u8]) -> Vec<u8> {
        let mut plaintext = Vec::with_capacity(attacker_input.len() + self.unknown_suffix.len());
        plaintext.extend_from_slice(attacker_input);
        plaintext.extend_from_slice(&self.unknown_suffix);
        aes128_ecb_encrypt(&self.key, &plaintext)
    }
}

/// Detect block size. Returns block_size (panic if not found up to 64).
fn find_block_size(oracle: &Oracle) -> usize {
    let init_len = oracle.encrypt(b"").len();
    for i in 1..=64usize {
        let test_input = vec![b'A'; i];
        let new_len = oracle.encrypt(&test_input).len();
        if new_len > init_len {
            return new_len - init_len;
        }
    }
    panic!("Could not find block size within 64 bytes");
}

/// Detect ECB via duplicate-block heuristic
fn detect_ecb(oracle: &Oracle, block_size: usize) -> bool {
    let plaintext = vec![b'A'; block_size * 4];
    let ciphertext = oracle.encrypt(&plaintext);
    let mut seen = HashSet::new();
    for chunk in ciphertext.chunks_exact(block_size) {
        if !seen.insert(chunk.to_vec()) {
            return true;
        }
    }
    false
}

/// Build dictionary for a given known_prefix so that the target unknown byte is the last byte of the block.
/// Returns map: ciphertext-block (Vec<u8>) -> candidate byte.
fn build_dictionary(oracle: &Oracle, known_prefix: &[u8], block_size: usize) -> HashMap<Vec<u8>, u8> {
    let mut dict = HashMap::new();

    // Padding to make the unknown byte align as the last byte of a block
    let padding_len = block_size - 1 - (known_prefix.len() % block_size);
    let mut prefix = vec![b'A'; padding_len];
    prefix.extend_from_slice(known_prefix);

    let current_block_index = known_prefix.len() / block_size;
    let target_block_offset = current_block_index * block_size;

    for b in 0u8..=255 {
        let mut probe = prefix.clone();
        probe.push(b);
        let ct = oracle.encrypt(&probe);
        if ct.len() >= target_block_offset + block_size {
            let block = ct[target_block_offset..target_block_offset + block_size].to_vec();
            dict.insert(block, b);
        }
    }

    dict
}

/// Crack next byte. Returns Some(byte) or None if no more bytes (likely padding/end).
fn crack_next_byte(oracle: &Oracle, known_bytes: &[u8], block_size: usize) -> Option<u8> {
    let current_block_index = known_bytes.len() / block_size;
    let target_block_offset = current_block_index * block_size;
    let padding_len = block_size - 1 - (known_bytes.len() % block_size);
    let short_input = vec![b'A'; padding_len];

    let target_ct = oracle.encrypt(&short_input);
    if target_ct.len() < target_block_offset + block_size {
        return None;
    }
    let target_block = target_ct[target_block_offset..target_block_offset + block_size].to_vec();

    let dict = build_dictionary(oracle, known_bytes, block_size);
    dict.get(&target_block).copied()
}

/// Primary exported function to run demo:
/// - key: Uint8Array (must be 16 bytes)
/// - attacker_input: &str (data the attacker supplies before unknown suffix; typically empty for classic attack)
/// - unknown: &str (the secret suffix to demonstrate recovery)
///
/// Returns a JS object { ciphertext: Uint8Array, recovered: Uint8Array, steps: Vec<String> }
#[wasm_bindgen]
pub fn run_ecb_demo(key: &Uint8Array, attacker_input: &str, unknown: &str) -> Object {
    // validate key length
    let k_vec = u8array_to_vec(key);
    if k_vec.len() != 16 {
        let obj = Object::new();
        js_sys::Reflect::set(&obj, &JsValue::from_str("ciphertext"), &Uint8Array::new_with_length(0)).unwrap();
        js_sys::Reflect::set(&obj, &JsValue::from_str("recovered"), &Uint8Array::new_with_length(0)).unwrap();
        js_sys::Reflect::set(&obj, &JsValue::from_str("steps"), &vec_to_js_array(vec![format!(
            "Invalid key length: {} (expected 16)",
            k_vec.len()
        )])).unwrap();
        return obj;
    }

    let mut key_arr = [0u8; 16];
    key_arr.copy_from_slice(&k_vec);

    let attacker_bytes = attacker_input.as_bytes();
    let unknown_bytes = unknown.as_bytes().to_vec();

    let oracle = Oracle::new(key_arr, unknown_bytes.clone());

    let mut full_plaintext = Vec::with_capacity(attacker_bytes.len() + unknown_bytes.len());
    full_plaintext.extend_from_slice(attacker_bytes);
    full_plaintext.extend_from_slice(&unknown_bytes);

    let ciphertext = oracle.encrypt(&full_plaintext);

    let mut steps: Vec<String> = Vec::new();
    steps.push(format!("Ciphertext length: {} bytes", ciphertext.len()));

    let block_size = find_block_size(&oracle);
    steps.push(format!("Detected block size: {}", block_size));

    if !detect_ecb(&oracle, block_size) {
        steps.push("ECB not detected; aborting attack".to_string());
        let obj = Object::new();
        js_sys::Reflect::set(&obj, &JsValue::from_str("ciphertext"), &Uint8Array::from(&ciphertext[..])).unwrap();
        js_sys::Reflect::set(&obj, &JsValue::from_str("recovered"), &Uint8Array::new_with_length(0)).unwrap();
        js_sys::Reflect::set(&obj, &JsValue::from_str("steps"), &vec_to_js_array(steps)).unwrap();
        return obj;
    }

    steps.push("ECB detected via repeated-block heuristic".to_string());

    let mut recovered: Vec<u8> = Vec::new();
    steps.push(format!("Beginning byte-at-a-time recovery (unknown length approx {})", unknown_bytes.len()));

    for _ in 0..ciphertext.len() {
        match crack_next_byte(&oracle, &recovered, block_size) {
            Some(b) => {
                recovered.push(b);
                steps.push(format!("Recovered byte {}: 0x{:02x} ({})", recovered.len(), b, display_char(b)));
            }
            None => {
                steps.push("No matching byte found — likely end of secret or padding reached".to_string());
                break;
            }
        }
    }

    let obj = Object::new();
    js_sys::Reflect::set(&obj, &JsValue::from_str("ciphertext"), &Uint8Array::from(&ciphertext[..])).unwrap();
    js_sys::Reflect::set(&obj, &JsValue::from_str("recovered"), &Uint8Array::from(&recovered[..])).unwrap();
    js_sys::Reflect::set(&obj, &JsValue::from_str("steps"), &vec_to_js_array(steps)).unwrap();

    obj
}

/// Helper to render a printable representation of a byte for logs
fn display_char(b: u8) -> String {
    if b.is_ascii_graphic() || b == b' ' || b == b'\n' || b == b'\r' || b == b'\t' {
        match std::str::from_utf8(&[b]) {
            Ok(s) => s.to_string(),
            Err(_) => format!("0x{:02x}", b),
        }
    } else {
        format!("0x{:02x}", b)
    }
}