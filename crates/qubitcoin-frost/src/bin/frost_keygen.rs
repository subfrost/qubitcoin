//! FROST 170/255 keygen tool for BIP-360.
//!
//! Generates the FROST threshold multisig, saves all shares and the public key
//! package to ~/.bip360/, and prints the P2MR witness program.

use qubitcoin_frost::{
    frost_group_key_to_p2mr_program, generate_frost_keys, group_verifying_key, save_all_shares,
};
use std::path::PathBuf;

fn main() {
    let output_dir = dirs();

    eprintln!("=== BIP-360 FROST 170/255 Key Generation ===");
    eprintln!();
    eprintln!("Output directory: {}", output_dir.display());
    eprintln!("Generating 170-of-255 FROST threshold keys...");
    eprintln!("(This takes ~40 seconds)");
    eprintln!();

    let (shares, pubkey_pkg) = generate_frost_keys(255, 170).expect("FROST keygen failed");

    eprintln!("Generated {} key shares (threshold: 170)", shares.len());

    // Save shares
    let shares_dir = output_dir.join("shares");
    save_all_shares(&shares, &pubkey_pkg, &shares_dir).expect("Failed to save shares");
    eprintln!("Saved {} signer key files to {}/", shares.len(), shares_dir.display());

    // Save public key package separately
    let pubkey_json = serde_json::to_string_pretty(&pubkey_pkg).expect("serialize pubkey pkg");
    let pubkey_path = output_dir.join("pubkey_package.json");
    std::fs::write(&pubkey_path, &pubkey_json).expect("write pubkey package");
    eprintln!("Saved public key package to {}", pubkey_path.display());

    // Compute group verifying key
    let xonly = group_verifying_key(&pubkey_pkg);
    eprintln!();
    eprintln!("Group verifying key (x-only): {}", hex::encode(&xonly));

    // Compute P2MR witness program
    let p2mr_program = frost_group_key_to_p2mr_program(&pubkey_pkg);
    eprintln!("P2MR witness program (merkle root): {}", hex::encode(&p2mr_program));

    // Build the scriptPubKey
    let script = qubitcoin_frost::build_p2mr_frost_script(&p2mr_program);
    eprintln!("P2MR scriptPubKey: {}", hex::encode(script.as_bytes()));
    eprintln!();

    // Print the Rust constant for embedding
    eprintln!("=== Rust constant for qday_seize.rs ===");
    eprintln!();
    print_rust_array("SEIZE_P2MR_PROGRAM", &p2mr_program);

    // Save the P2MR program to a file for reference
    let p2mr_path = output_dir.join("p2mr_program.hex");
    std::fs::write(&p2mr_path, hex::encode(&p2mr_program)).expect("write p2mr program");

    let summary_path = output_dir.join("summary.txt");
    let summary = format!(
        "BIP-360 FROST 170/255 Key Generation Summary\n\
         ==============================================\n\
         Signers: 255\n\
         Threshold: 170\n\
         Group verifying key (x-only): {}\n\
         P2MR witness program: {}\n\
         P2MR scriptPubKey: {}\n",
        hex::encode(&xonly),
        hex::encode(&p2mr_program),
        hex::encode(script.as_bytes()),
    );
    std::fs::write(&summary_path, &summary).expect("write summary");
    eprintln!("Summary saved to {}", summary_path.display());
}

fn dirs() -> PathBuf {
    let home = std::env::var("HOME").expect("HOME not set");
    let dir = PathBuf::from(home).join(".bip360");
    std::fs::create_dir_all(&dir).expect("create ~/.bip360");
    dir
}

fn print_rust_array(name: &str, data: &[u8; 32]) {
    print!("pub const {}: [u8; 32] = [\n    ", name);
    for (i, byte) in data.iter().enumerate() {
        if i > 0 && i % 8 == 0 {
            print!("\n    ");
        }
        print!("0x{:02x}, ", byte);
    }
    println!("\n];");
}
