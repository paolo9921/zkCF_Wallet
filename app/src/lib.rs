// Re-export the functions we need for benchmarking
pub use crate::bin::main::{
    prove_pkcs7_verification,
    extract_certificate_data,
    convert_to_bytes,
};

pub mod bin {
    pub mod main;
}