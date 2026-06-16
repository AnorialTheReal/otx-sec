use sha2::{Digest, Sha256};
use std::env;
use std::fs::File;
use std::io::{Read, Result};

fn read_file(path: &str) -> Result<Vec<u8>> {
    let mut file = File::open(path)?;
    let mut data = Vec::new();

    file.read_to_end(&mut data)?;

    Ok(data)
}

fn sha256_bytes(data: &[u8]) -> String {
    let mut hasher = Sha256::new();

    hasher.update(data);

    hex::encode(hasher.finalize())
}

fn entropy_bytes(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }

    let mut counts = [0u64; 256];

    for byte in data {
        counts[*byte as usize] += 1;
    }

    let size = data.len() as f64;
    let mut entropy = 0.0;

    for count in counts {
        if count == 0 {
            continue;
        }

        let p = count as f64 / size;
        entropy -= p * p.log2();
    }

    entropy
}

fn extract_strings(data: &[u8], min_len: usize) -> Vec<String> {
    let mut strings = Vec::new();
    let mut current = Vec::new();

    for byte in data {
        if byte.is_ascii_graphic() || *byte == b' ' {
            current.push(*byte);
        } else {
            if current.len() >= min_len {
                strings.push(String::from_utf8_lossy(&current).to_string());
            }

            current.clear();
        }
    }

    if current.len() >= min_len {
        strings.push(String::from_utf8_lossy(&current).to_string());
    }

    strings
}

fn is_elf(data: &[u8]) -> bool {
    data.starts_with(b"\x7fELF")
}

fn elf_arch(data: &[u8]) -> String {
    if data.len() < 20 || !is_elf(data) {
        return "unknown".to_string();
    }

    let machine = u16::from_le_bytes([data[18], data[19]]);

    match machine {
        0x03 => "x86".to_string(),
        0x3e => "x86_64".to_string(),
        0x28 => "arm".to_string(),
        0xb7 => "aarch64".to_string(),
        _ => format!("unknown_0x{:x}", machine),
    }
}

fn is_pe(data: &[u8]) -> bool {
    if data.len() < 0x40 || !data.starts_with(b"MZ") {
        return false;
    }

    let pe_offset = u32::from_le_bytes([data[0x3c], data[0x3d], data[0x3e], data[0x3f]]) as usize;

    if data.len() < pe_offset + 4 {
        return false;
    }

    &data[pe_offset..pe_offset + 4] == b"PE\0\0"
}

fn pe_arch(data: &[u8]) -> String {
    if data.len() < 0x40 || !is_pe(data) {
        return "unknown".to_string();
    }

    let pe_offset = u32::from_le_bytes([data[0x3c], data[0x3d], data[0x3e], data[0x3f]]) as usize;

    if data.len() < pe_offset + 6 {
        return "unknown".to_string();
    }

    let machine = u16::from_le_bytes([data[pe_offset + 4], data[pe_offset + 5]]);

    match machine {
        0x014c => "x86".to_string(),
        0x8664 => "x86_64".to_string(),
        0x01c0 => "arm".to_string(),
        0xaa64 => "aarch64".to_string(),
        _ => format!("unknown_0x{:x}", machine),
    }
}

fn suspicious_string_hits(strings: &[String]) -> Vec<String> {
    let markers = [
        "/bin/sh",
        "/bin/bash",
        "curl ",
        "wget ",
        "chmod +x",
        "base64",
        "eval(",
        "exec(",
        "system(",
        "LD_PRELOAD",
        "/etc/ld.so.preload",
        "/etc/shadow",
        "/etc/passwd",
        "authorized_keys",
        "id_rsa",
        "id_ed25519",
        "crontab",
        "systemctl enable",
        "/tmp/",
        "/dev/shm/",
        "docker.sock",
        "kubectl",
        "xmrig",
        "stratum+tcp",
    ];

    let mut hits = Vec::new();

    for marker in markers {
        for item in strings {
            if item.to_lowercase().contains(&marker.to_lowercase()) {
                hits.push(marker.to_string());
                break;
            }
        }
    }

    hits
}

fn main() {
    let args: Vec<String> = env::args().collect();

    if args.len() != 2 {
        eprintln!("Usage: otxscan <file>");
        std::process::exit(1);
    }

    let path = &args[1];

    match read_file(path) {
        Ok(data) => {
            let sha256 = sha256_bytes(&data);
            let entropy = entropy_bytes(&data);
            let strings = extract_strings(&data, 4);
            let hits = suspicious_string_hits(&strings);

            let is_elf_file = is_elf(&data);
            let is_pe_file = is_pe(&data);

            let mut risk_score = 0;
            let mut reasons: Vec<String> = Vec::new();

            if is_elf_file {
                risk_score += 10;
                reasons.push("elf_file".to_string());
            }

            if is_pe_file {
                risk_score += 10;
                reasons.push("pe_file".to_string());
            }

            if entropy >= 7.8 {
                risk_score += 40;
                reasons.push("very_high_entropy".to_string());
            } else if entropy >= 7.2 {
                risk_score += 25;
                reasons.push("high_entropy".to_string());
            }

            for hit in &hits {
                risk_score += 8;
                reasons.push(format!("string_marker:{}", hit));
            }

            if risk_score > 100 {
                risk_score = 100;
            }

            let output = serde_json::json!({
                "engine": "otx-rust",
                "version": "0.1.2-alpha",
                "path": path,
                "sha256": sha256,
                "size": data.len(),
                "entropy": (entropy * 10000.0).round() / 10000.0,
                "is_elf": is_elf_file,
                "elf_arch": elf_arch(&data),
                "is_pe": is_pe_file,
                "pe_arch": pe_arch(&data),
                "string_count": strings.len(),
                "suspicious_strings": hits,
                "risk_score": risk_score,
                "reasons": reasons
            });

            println!("{}", output);
        }
        Err(error) => {
            let output = serde_json::json!({
                "engine": "otx-rust",
                "version": "0.1.2-alpha",
                "error": error.to_string()
            });

            println!("{}", output);
            std::process::exit(2);
        }
    }
}
