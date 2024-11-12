use criterion::{
    black_box, criterion_group, criterion_main, Criterion,
    BenchmarkId, Throughput,
};
use std::fs;
use std::path::Path;
use pkcs7_core::pkcs7::load_pkcs7;  // Import directly from core crate

#[derive(Debug)]
struct TestFile {
    name: String,
    content: Vec<u8>,
    size: u64,
}

fn load_test_files(dir: &Path) -> Vec<TestFile> {
    println!("Attempting to load files from: {}", dir.display());
    
    if !dir.exists() {
        panic!("Test files directory does not exist: {}", dir.display());
    }

    let mut files = Vec::new();
    
    match fs::read_dir(dir) {
        Ok(entries) => {
            for entry in entries.flatten() {
                let path = entry.path();
                println!("Found file: {}", path.display());
                
                if let Some(ext) = path.extension() {
                    if ext == "p7m" {
                        match fs::read(&path) {
                            Ok(content) => {
                                println!("Successfully loaded file: {}", path.display());
                                println!("Size: {} bytes", content.len());
                                
                                files.push(TestFile {
                                    name: path.file_name().unwrap().to_string_lossy().into_owned(),
                                    size: content.len() as u64,
                                    content,
                                });
                            }
                            Err(e) => println!("Error reading file {}: {}", path.display(), e),
                        }
                    }
                }
            }
        }
        Err(e) => panic!("Error reading directory: {}", e),
    }

    if files.is_empty() {
        panic!("No .p7m files found in {}", dir.display());
    }

    println!("\nLoaded {} DER test files", files.len());
    files
}

fn bench_pkcs7_parsing(c: &mut Criterion) {
    println!("Starting PKCS#7 parsing benchmarks");
    
    let mut group = c.benchmark_group("pkcs7_parsing");
    group.sample_size(30);
    group.measurement_time(std::time::Duration::from_secs(5));
    
    println!("\nRunning PKCS#7 parsing benchmarks");
    println!("================================");

    // Try multiple possible paths to find test files
    let possible_paths = vec![
        Path::new("benches/test_files/pkcs7"),
        Path::new("../core/benches/test_files/pkcs7"),  // Look in core crate
        Path::new("test_files/pkcs7"),
    ];

    let test_files = possible_paths
        .iter()
        .find(|&path| {
            println!("Checking path: {}", path.display());
            path.exists()
        })
        .map(|path| load_test_files(path))
        .expect("Could not find test files directory in any of the expected locations");
    
    let mut files = test_files;
    files.sort_by_key(|f| f.size);

    for file in files {
        println!("\nProcessing: {} ({} bytes)", file.name, file.size);
        
        if let Ok(_) = load_pkcs7(&file.content) {
            println!("Benchmarking...");
            group.throughput(Throughput::Bytes(file.size));
            group.bench_with_input(
                BenchmarkId::new("parse", &file.name),
                &file.content,
                |b, content| {
                    b.iter(|| {
                        black_box(load_pkcs7(content))
                            .expect("Parse failed during benchmark")
                    });
                },
            );
        } else {
            println!("Skipping due to parsing issues");
        }
    }
    
    group.finish();
}

criterion_group! {
    name = benches;
    config = Criterion::default()
        .sample_size(30)
        .measurement_time(std::time::Duration::from_secs(5))
        .confidence_level(0.95)
        .with_plots();
    targets = bench_pkcs7_parsing
}
criterion_main!(benches);