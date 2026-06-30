//! Re-encode an upki revocation cache directory so every clubcard
//! filter is in V4 format.
//!
//! `upki fetch` currently fetches V3 clubcard filters, which the Go
//! consumer (`go-upki`) doesn't parse. This tool reads a source
//! cache directory, re-encodes each filter file as V4, copies
//! `index.bin` verbatim, and rewrites `manifest.json` with the new
//! sizes and SHA-256 hashes so the destination directory is internally
//! consistent.
//!
//! Usage:
//!
//!     crlite-reencode --src <upki cache dir> --dest <output cache dir>
//!
//! Both directories must contain (or in --dest's case, will get) a
//! `revocation/` subdirectory matching the upki on-disk layout.

use std::error::Error;
use std::fs;
use std::path::PathBuf;

use clap::Parser;
use clubcard_crlite::{CRLiteClubcard, Encoding};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

fn main() -> Result<(), Box<dyn Error>> {
    let args = Args::parse();

    let src_rev = args.src.join("revocation");
    let dest_rev = args.dest.join("revocation");

    if !src_rev.is_dir() {
        return Err(format!(
            "source revocation dir does not exist: {}",
            src_rev.display()
        )
        .into());
    }
    fs::create_dir_all(&dest_rev)?;

    let manifest_bytes = fs::read(src_rev.join("manifest.json"))?;
    let mut manifest: Manifest = serde_json::from_slice(&manifest_bytes)?;

    // index.bin contents are independent of the filter encoding, so
    // a verbatim copy stays valid for V4 filters.
    fs::copy(src_rev.join("index.bin"), dest_rev.join("index.bin"))?;

    for entry in manifest.files.iter_mut() {
        let src_path = src_rev.join(&entry.filename);
        let dest_path = dest_rev.join(&entry.filename);

        let bytes = fs::read(&src_path)?;
        let original_size = bytes.len();

        let clubcard = CRLiteClubcard::from_bytes(&bytes)
            .map_err(|e| format!("decoding {}: {:?}", entry.filename, e))?;
        let encoded = clubcard
            .to_bytes(Encoding::V4)
            .map_err(|e| format!("re-encoding {}: {:?}", entry.filename, e))?;

        fs::write(&dest_path, &encoded)?;

        let new_size = encoded.len();
        let new_hash = Sha256::digest(&encoded).to_vec();

        println!(
            "{}: {} -> {} bytes ({:.2}x)",
            entry.filename,
            original_size,
            new_size,
            new_size as f64 / original_size as f64,
        );

        entry.size = new_size;
        entry.hash = new_hash;
    }

    // Rewrite the manifest with updated sizes + hashes so the dest cache
    // is self-consistent. comment is preserved as-is; generated_at is
    // preserved so go-upki's freshness signal stays meaningful.
    let new_manifest = serde_json::to_vec(&manifest)?;
    fs::write(dest_rev.join("manifest.json"), &new_manifest)?;

    println!(
        "wrote {} filter(s) + index.bin + manifest.json to {}",
        manifest.files.len(),
        dest_rev.display(),
    );

    Ok(())
}


#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    /// Source upki cache directory (containing revocation/manifest.json + index.bin + filters).
    #[arg(long)]
    src: PathBuf,

    /// Destination cache directory. revocation/ will be created if absent.
    #[arg(long)]
    dest: PathBuf,
}

#[derive(Debug, Deserialize, Serialize)]
struct Manifest {
    generated_at: u64,
    comment: String,
    files: Vec<ManifestFile>,
}

#[derive(Debug, Deserialize, Serialize)]
struct ManifestFile {
    filename: String,
    size: usize,
    #[serde(with = "hex::serde")]
    hash: Vec<u8>,
}
