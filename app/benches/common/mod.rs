use std::fs;
use std::path::Path;

#[derive(Debug)]
pub struct TestFile {
    pub name: String,
    pub content: Vec<u8>,
    pub size: u64,
}

pub fn load_test_files(dir: &Path) -> Vec<TestFile> {
    println!("Loading test files from: {}", dir.display());
    let mut files = Vec::new();
    
    if let Ok(entries) = fs::read_dir(dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if let Some(ext) = path.extension() {
                if ext == "p7m" {
                    if let Ok(content) = fs::read(&path) {
                        println!("Loaded file: {}", path.display());
                        println!("Size: {} bytes", content.len());
                        
                        files.push(TestFile {
                            name: path.file_name().unwrap().to_string_lossy().into_owned(),
                            size: content.len() as u64,
                            content,
                        });
                    }
                }
            }
        }
    }

    println!("\nLoaded {} test files", files.len());
    files
}