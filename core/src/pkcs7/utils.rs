// src/pkcs7/utils.rs
use crate::pkcs7::structs::Pkcs7;
use std::fs::File;
use std::io::Read;

use std::fs;
use std::path::Path;
use bcder::decode::IntoSource;
use bcder::decode::{self, Constructed, DecodeError};
use bcder::{Mode, Oid, Tag};
use chrono::{NaiveDateTime, TimeZone, Utc};
use hex;
use serde::{Deserialize, Serialize};
use std::fmt;
use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;


#[derive(Debug)]
pub enum Pkcs7Format {
    PEM,
    DER
}

/// Load PKCS#7 data either from a file path or from raw bytes
pub fn load_pkcs7<T: AsRef<[u8]>>(input: T) -> Result<Pkcs7, Box<dyn std::error::Error>> {
    let content = if let Ok(path_str) = String::from_utf8(input.as_ref().to_vec()) {
        if Path::new(&path_str).exists() {
            // If input is a valid path, read the file
            fs::read(path_str)?
        } else {
            // If input is not a path, treat it as raw bytes
            input.as_ref().to_vec()
        }
    } else {
        // If input is not valid UTF-8, treat it as raw bytes
        input.as_ref().to_vec()
    };

    // Detect format and parse accordingly
    let format = detect_format(&content);
    parse_pkcs7_content(&content, format)
}

/// Detect if the content is PEM or DER format
fn detect_format(content: &[u8]) -> Pkcs7Format {
    // Check if content starts with PEM header
    if content.starts_with(b"-----BEGIN") {
        Pkcs7Format::PEM
    } else {
        Pkcs7Format::DER
    }
}

/// Parse PKCS#7 content based on detected format
fn parse_pkcs7_content(content: &[u8], format: Pkcs7Format) -> Result<Pkcs7, Box<dyn std::error::Error>> {
    match format {
        Pkcs7Format::PEM => parse_pem(content),
        Pkcs7Format::DER => parse_der(content),
    }
}

/// Parse PEM formatted PKCS#7 data
fn parse_pem(content: &[u8]) -> Result<Pkcs7, Box<dyn std::error::Error>> {
    // Convert content to string for PEM processing
    let content_str = String::from_utf8(content.to_vec())?;
    
    // Find the PEM boundaries
    let start_marker = "-----BEGIN PKCS7-----";
    let end_marker = "-----END PKCS7-----";
    
    let start = content_str.find(start_marker)
        .ok_or("Invalid PEM: missing start marker")?;
    let end = content_str.find(end_marker)
        .ok_or("Invalid PEM: missing end marker")?;
    
    // Extract the base64 content
    let base64_content = content_str[start + start_marker.len()..end]
        .replace('\n', "")
        .replace('\r', "");
    
    // Decode base64 to get DER bytes
    let der_bytes = BASE64.decode(base64_content.trim())?;
    
    // Parse the DER content
    parse_der(&der_bytes)
}

/// Parse DER formatted PKCS#7 data
fn parse_der(content: &[u8]) -> Result<Pkcs7, Box<dyn std::error::Error>> {
    let source = content.into_source();
    let pkcs7 = Constructed::decode(source, Mode::Der, |constructed| {
        Pkcs7::take_from(constructed)
    }).map_err(|e| format!("Failed to decode DER: {}", e))?;

    Ok(pkcs7)
}

/// Log parsing information (useful for debugging)
fn log_parsing_info(format: &Pkcs7Format, content: &[u8]) {
    println!(
        "Parsing PKCS#7 data: format={:?}, size={} bytes",
        format,
        content.len()
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn test_der_parsing() {
        // Use the test files created by prepare_test_files
        let test_file = "benches/test_files/pkcs7/ecdsa_1KB.p7m";
        let content = fs::read(test_file).expect("Failed to read test file");
        let result = parse_der(&content);
        assert!(result.is_ok(), "Failed to parse DER: {:?}", result.err());
    }

    #[test]
    fn test_detect_format() {
        let test_file_der = "benches/test_files/pkcs7/ecdsa_1KB.p7m";
        let test_file_pem = "benches/test_files/pkcs7/ecdsa_1KB.pem";
        
        let der_content = fs::read(test_file_der).expect("Failed to read DER test file");
        let pem_content = fs::read(test_file_pem).expect("Failed to read PEM test file");
        
        assert!(matches!(detect_format(&der_content), Pkcs7Format::DER));
        assert!(matches!(detect_format(&pem_content), Pkcs7Format::PEM));
    }

    #[test]
    fn test_load_from_path() {
        let test_file = "benches/test_files/pkcs7/ecdsa_1KB.p7m";
        let result = load_pkcs7(test_file);
        assert!(result.is_ok(), "Failed to load from path: {:?}", result.err());
    }

    #[test]
    fn test_load_from_bytes() {
        let test_file = "benches/test_files/pkcs7/ecdsa_1KB.p7m";
        let content = fs::read(test_file).expect("Failed to read test file");
        let result = load_pkcs7(content);
        assert!(result.is_ok(), "Failed to load from bytes: {:?}", result.err());
    }

    #[test]
    fn test_pem_parsing() {
        let test_file = "benches/test_files/pkcs7/ecdsa_1KB.pem";
        let content = fs::read(test_file).expect("Failed to read test file");
        let result = parse_pem(&content);
        assert!(result.is_ok(), "Failed to parse PEM: {:?}", result.err());
    }

    // Helper function to print signature details for debugging
    fn debug_signature(signature_bytes: &[u8]) {
        println!("Signature length: {}", signature_bytes.len());
        println!("First few bytes: {:?}", &signature_bytes[..std::cmp::min(10, signature_bytes.len())]);
        if signature_bytes.len() >= 2 {
            println!("ASN.1 length byte: {}", signature_bytes[1]);
        }
    }

}