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

fn is_elf(data: &[u8]) -> bool {
    data.starts_with(b"\x7fELF")
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
            let elf = is_elf(&data);

            println!(
                "{{\"sha256\":\"{}\",\"size\":{},\"entropy\":{:.4},\"is_elf\":{}}}",
                sha256,
                data.len(),
                entropy,
                elf
            );
        }
        Err(error) => {
            eprintln!("error: {}", error);
            std::process::exit(2);
        }
    }
}
