use std::time::{Instant, Duration};
use std::fs::File;
use std::io::Write;
use pkcs7_core::pkcs7::{load_pkcs7, PublicKey};
use std::time::{SystemTime, UNIX_EPOCH};
use app::bin::main::{prove_pkcs7_verification, extract_validation_data, convert_to_bytes};
use std::path::PathBuf;

fn find_test_file(filename: &str) -> Option<PathBuf> {
    let possible_paths = [
        "benches/test_files/pkcs7",
        "../benches/test_files/pkcs7",
        "app/benches/test_files/pkcs7",
        "../../benches/test_files/pkcs7",
    ];

    for base_path in possible_paths.iter() {
        let full_path = PathBuf::from(base_path).join(filename);
        println!("Trying path: {}", full_path.display());
        if full_path.exists() {
            return Some(full_path);
        }
    }
    None
}

fn main() {
    println!("\nZKP Generation Performance Measurement");
    println!("====================================");

    // Configuration
    let iterations = 3;
    let test_filename = "rsa_1KB.p7m";
    
    // Find the test file
    let test_file = find_test_file(test_filename)
        .expect("Could not find test file in any of the expected locations");
    
    println!("\nFound test file at: {}", test_file.display());

    let mut measurements = Vec::new();
    let mut report = String::new();
    report.push_str("ZKP Generation Performance Measurements\n");
    report.push_str("=====================================\n\n");

    // Load and prepare test data
    println!("Loading test file...");
    let content = std::fs::read(&test_file).expect("Failed to read test file");
    let pkcs7 = load_pkcs7("/home/moz/tesi/cert/rsa/cf_bin_signed.p7m").expect("Failed to parse PKCS7");
    
    let signer_info = &pkcs7.content.signer_infos[0];
    let subject_cert = pkcs7.content.certs.iter()
        .find(|cert| &cert.tbs_certificate.serial_number == &signer_info.signer_identifier.serial_number)
        .expect("Subject certificate not found");

    let (chain_data, crl_data) = extract_validation_data(&pkcs7.content, &subject_cert);
    let econtent = convert_to_bytes(pkcs7.content.content_info.e_content.clone());
    let salt = vec![1, 2, 3, 4];
    let msg = if signer_info.auth_attributes.is_some() {
        signer_info.auth_bytes.clone()
    } else {
        pkcs7.content_bytes.clone()
    };
    let signature = signer_info.signature.clone();
    let public_key = &subject_cert.tbs_certificate.subject_public_key_info.subject_public_key;
    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();

    // Run measurements
    for i in 1..=iterations {
        println!("\nIteration {}/{}", i, iterations);
        
        let start = Instant::now();
        let result = match public_key {
            PublicKey::Rsa { modulus, exponent } => {
                prove_pkcs7_verification(
                    &chain_data, &crl_data, &econtent, &salt, &msg,
                    &signature, modulus, Some(exponent), now
                )
            }
            PublicKey::Ecdsa { point } => {
                prove_pkcs7_verification(
                    &chain_data, &crl_data, &econtent, &salt, &msg,
                    &signature, point, None, now
                )
            }
        };
        let duration = start.elapsed();
        
        // Verify successful generation
        if result.journal.bytes.len() > 0 {
            println!("Proof generated successfully");
            println!("Time taken: {:?}", duration);
            measurements.push(duration);
            report.push_str(&format!("Run {}: {:?}\n", i, duration));
        } else {
            println!("Warning: Proof generation might have failed");
        }
    }

    // Calculate statistics
    if !measurements.is_empty() {
        let total_time: Duration = measurements.iter().sum();
        let avg_time = total_time / measurements.len() as u32;
        let max_time = measurements.iter().max().unwrap();
        let min_time = measurements.iter().min().unwrap();
        
        report.push_str("\nSummary:\n");
        report.push_str(&format!("Average time: {:?}\n", avg_time));
        report.push_str(&format!("Minimum time: {:?}\n", min_time));
        report.push_str(&format!("Maximum time: {:?}\n", max_time));
        report.push_str(&format!("Total time for {} iterations: {:?}\n", iterations, total_time));

        println!("\nResults Summary:");
        println!("Average time: {:?}", avg_time);
        println!("Min time: {:?}", min_time);
        println!("Max time: {:?}", max_time);
        
        // Save report
        let report_file = "zkp_performance_report.txt";
        File::create(report_file)
            .unwrap()
            .write_all(report.as_bytes())
            .unwrap();
        
        println!("\nDetailed results saved to {}", report_file);
    }
}