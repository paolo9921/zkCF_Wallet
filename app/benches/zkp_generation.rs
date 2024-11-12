use app::{prove_pkcs7_verification, extract_certificate_data, convert_to_bytes};

use criterion::{criterion_group, criterion_main, Criterion, BenchmarkId};
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use pkcs7_core::pkcs7::{load_pkcs7, PublicKey};
use methods::PKCS7_VERIFY_ELF;

mod common;

pub fn bench_proof_generation(c: &mut Criterion) {
    let mut group = c.benchmark_group("zkp_proof_generation");
    // Minimum required samples for Criterion
    group.sample_size(10);
    // Reduced measurement time per sample
    group.measurement_time(std::time::Duration::from_secs(30));
    
    println!("Loading test files...");
    let test_files = common::load_test_files(Path::new("benches/test_files/pkcs7"));
    
    // Test only with the smallest RSA file
    if let Some(test_file) = test_files.iter().find(|f| f.name == "rsa_1KB.p7m") {
        println!("Testing with file: {} ({} bytes)", test_file.name, test_file.size);

        if let Ok(pkcs7) = load_pkcs7(&test_file.content) {
            let signer_info = &pkcs7.content.signer_infos[0];
            let subject_cert = pkcs7.content.certs.iter()
                .find(|cert| &cert.tbs_certificate.serial_number == &signer_info.signer_identifier.serial_number)
                .expect("Subject certificate not found");

            println!("Preparing data for ZKP...");
            let chain_data = extract_certificate_data(&pkcs7.content.certs, &subject_cert);
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
            
            println!("Starting benchmark for ZKP generation...");
            group.bench_function(
                BenchmarkId::new("prove_rsa_1kb", "single_run"),
                |b| {
                    b.iter(|| {
                        match public_key {
                            PublicKey::Rsa { modulus, exponent } => {
                                prove_pkcs7_verification(
                                    &chain_data, &econtent, &salt, &msg,
                                    &signature, modulus, Some(exponent), now
                                )
                            }
                            _ => panic!("Expected RSA key")
                        }
                    });
                },
            );
            println!("Benchmark completed");
        }
    } else {
        println!("Couldn't find RSA 1KB test file!");
    }
    
    group.finish();
}

criterion_group! {
    name = benches;
    config = Criterion::default()
        .sample_size(10)  // Minimum required by Criterion
        .measurement_time(std::time::Duration::from_secs(30))
        .confidence_level(0.95)
        .without_plots();  // Disable plot generation to save memory
    targets = bench_proof_generation
}
criterion_main!(benches);