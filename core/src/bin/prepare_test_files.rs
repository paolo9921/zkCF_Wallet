use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::io;

const TEST_DATA_SIZES: &[(usize, &str)] = &[
    (1024, "1KB"),
    (10 * 1024, "10KB"),
    (100 * 1024, "100KB"),
    (1024 * 1024, "1MB"),
];

struct TestEnvironment {
    root_dir: PathBuf,
    certs_dir: PathBuf,
    data_dir: PathBuf,
    output_dir: PathBuf,
}

impl TestEnvironment {
    fn new() -> io::Result<TestEnvironment> {  // Changed return type to TestEnvironment
        let root_dir = PathBuf::from("benches/test_files");
        let certs_dir = root_dir.join("certs");
        let data_dir = root_dir.join("data");
        let output_dir = root_dir.join("pkcs7");

        // Create directories
        for dir in [&root_dir, &certs_dir, &data_dir, &output_dir] {
            fs::create_dir_all(dir)?;
        }

        Ok(TestEnvironment {
            root_dir,
            certs_dir,
            data_dir,
            output_dir,
        })
    }

    // Rest of the implementation remains the same...
    fn generate_certificates(&self) -> io::Result<()> {
        println!("Generating RSA certificates...");
        self.generate_root_ca("rsa_root", "rsa:4096")?;
        self.generate_intermediate("rsa_inter", "rsa_root", "rsa:2048")?;
        self.generate_user_cert("rsa_user", "rsa_inter", "rsa:2048")?;

        println!("Generating ECDSA certificates...");
        self.generate_root_ca("ecdsa_root", "ec -pkeyopt ec_paramgen_curve:prime256v1")?;
        self.generate_intermediate("ecdsa_inter", "ecdsa_root", "ec -pkeyopt ec_paramgen_curve:prime256v1")?;
        self.generate_user_cert("ecdsa_user", "ecdsa_inter", "ec -pkeyopt ec_paramgen_curve:prime256v1")?;

        Ok(())
    }

    fn generate_root_ca(&self, name: &str, key_params: &str) -> io::Result<()> {
        println!("Generating {} root CA...", name);
        
        // Generate private key
        let output = Command::new("openssl")
            .args(["genpkey", "-algorithm"])
            .args(key_params.split_whitespace())
            .arg("-out")
            .arg(self.certs_dir.join(format!("{}_key.pem", name)))
            .output()?;

        if !output.status.success() {
            return Err(io::Error::new(
                io::ErrorKind::Other,
                format!("Failed to generate root CA key: {:?}", String::from_utf8_lossy(&output.stderr))
            ));
        }

        // Generate root certificate
        let output = Command::new("openssl")
            .args(["req", "-new", "-x509"])
            .args(["-key", &self.certs_dir.join(format!("{}_key.pem", name)).to_string_lossy()])
            .args(["-out", &self.certs_dir.join(format!("{}_cert.pem", name)).to_string_lossy()])
            .args(["-days", "365"])
            .arg("-subj")
            .arg(format!("/CN={} Root CA/O=Test Org/C=IT", name))
            .output()?;

        if !output.status.success() {
            return Err(io::Error::new(
                io::ErrorKind::Other,
                format!("Failed to generate root certificate: {:?}", String::from_utf8_lossy(&output.stderr))
            ));
        }

        Ok(())
    }

    fn generate_intermediate(&self, name: &str, parent: &str, key_params: &str) -> io::Result<()> {
        println!("Generating {} intermediate CA...", name);
        
        // Generate intermediate key
        let output = Command::new("openssl")
            .args(["genpkey", "-algorithm"])
            .args(key_params.split_whitespace())
            .arg("-out")
            .arg(self.certs_dir.join(format!("{}_key.pem", name)))
            .output()?;

        if !output.status.success() {
            return Err(io::Error::new(
                io::ErrorKind::Other,
                format!("Failed to generate intermediate key: {:?}", String::from_utf8_lossy(&output.stderr))
            ));
        }

        // Generate CSR
        let output = Command::new("openssl")
            .args(["req", "-new"])
            .args(["-key", &self.certs_dir.join(format!("{}_key.pem", name)).to_string_lossy()])
            .args(["-out", &self.certs_dir.join(format!("{}_csr.pem", name)).to_string_lossy()])
            .arg("-subj")
            .arg(format!("/CN={} Intermediate CA/O=Test Org/C=IT", name))
            .output()?;

        if !output.status.success() {
            return Err(io::Error::new(
                io::ErrorKind::Other,
                format!("Failed to generate CSR: {:?}", String::from_utf8_lossy(&output.stderr))
            ));
        }

        // Sign intermediate certificate
        let output = Command::new("openssl")
            .args(["x509", "-req"])
            .args(["-in", &self.certs_dir.join(format!("{}_csr.pem", name)).to_string_lossy()])
            .args(["-CA", &self.certs_dir.join(format!("{}_cert.pem", parent)).to_string_lossy()])
            .args(["-CAkey", &self.certs_dir.join(format!("{}_key.pem", parent)).to_string_lossy()])
            .arg("-CAcreateserial")
            .args(["-out", &self.certs_dir.join(format!("{}_cert.pem", name)).to_string_lossy()])
            .args(["-days", "365"])
            .output()?;

        if !output.status.success() {
            return Err(io::Error::new(
                io::ErrorKind::Other,
                format!("Failed to sign intermediate certificate: {:?}", String::from_utf8_lossy(&output.stderr))
            ));
        }

        Ok(())
    }

    fn generate_user_cert(&self, name: &str, parent: &str, key_params: &str) -> io::Result<()> {
        println!("Generating {} user certificate...", name);
        self.generate_intermediate(name, parent, key_params)
    }

    fn generate_test_data(&self) -> io::Result<()> {
        println!("Generating test data files...");
        for (size, label) in TEST_DATA_SIZES {
            println!("Creating {} test file...", label);
            let data = vec![b'A'; *size];
            fs::write(
                self.data_dir.join(format!("data_{}.txt", label)),
                data,
            )?;
        }
        Ok(())
    }

    fn create_pkcs7_files(&self) -> io::Result<()> {
        println!("Creating PKCS#7 files...");
        for (_, size_label) in TEST_DATA_SIZES {
            // Create RSA PKCS#7 files
            println!("Creating RSA PKCS#7 for {} file...", size_label);
            self.create_pkcs7(
                &format!("data_{}.txt", size_label),
                &format!("rsa_{}.p7m", size_label),
                "rsa_user",
            )?;

            // Create ECDSA PKCS#7 files
            println!("Creating ECDSA PKCS#7 for {} file...", size_label);
            self.create_pkcs7(
                &format!("data_{}.txt", size_label),
                &format!("ecdsa_{}.p7m", size_label),
                "ecdsa_user",
            )?;

            // Convert to PEM
            println!("Converting {} files to PEM format...", size_label);
            self.convert_der_to_pem(
                &format!("rsa_{}.p7m", size_label),
                &format!("rsa_{}.pem", size_label),
            )?;
            self.convert_der_to_pem(
                &format!("ecdsa_{}.p7m", size_label),
                &format!("ecdsa_{}.pem", size_label),
            )?;
        }
        Ok(())
    }

    fn create_pkcs7(&self, data_file: &str, output_file: &str, signer: &str) -> io::Result<()> {
        // Extract signer type (rsa or ecdsa) from signer name
        let signer_type = if signer.starts_with("rsa") { "rsa" } else { "ecdsa" };
        
        let output = Command::new("openssl")
            .args(["cms", "-sign", "-binary", "-nodetach"])
            .args(["-in", &self.data_dir.join(data_file).to_string_lossy()])
            .args(["-signer", &self.certs_dir.join(format!("{}_cert.pem", signer)).to_string_lossy()])
            .args(["-inkey", &self.certs_dir.join(format!("{}_key.pem", signer)).to_string_lossy()])
            // Add intermediate and root certificates
            .args(["-certfile", &self.certs_dir.join(format!("{}_inter_cert.pem", signer_type)).to_string_lossy()])
            .args(["-certfile", &self.certs_dir.join(format!("{}_root_cert.pem", signer_type)).to_string_lossy()])
            .args(["-out", &self.output_dir.join(output_file).to_string_lossy()])
            .args(["-outform", "DER"])
            .output()?;

        if !output.status.success() {
            return Err(io::Error::new(
                io::ErrorKind::Other,
                format!("Failed to create PKCS#7 file: {:?}", String::from_utf8_lossy(&output.stderr))
            ));
        }

        Ok(())
    }

    fn convert_der_to_pem(&self, der_file: &str, pem_file: &str) -> io::Result<()> {
        let output = Command::new("openssl")
            .args(["cms", "-verify", "-noverify"]) // Add -verify operation and skip cert verification
            .args(["-in", &self.output_dir.join(der_file).to_string_lossy()])
            .args(["-inform", "DER"])
            .args(["-out", &self.output_dir.join(pem_file).to_string_lossy()])
            .args(["-outform", "PEM"])
            .output()?;

        if !output.status.success() {
            return Err(io::Error::new(
                io::ErrorKind::Other,
                format!("Failed to convert DER to PEM: {:?}", String::from_utf8_lossy(&output.stderr))
            ));
        }

        Ok(())
    }
}

fn main() -> io::Result<()> {
    println!("Starting test files preparation...");
    println!("==================================");
    
    let env = TestEnvironment::new()?;
    
    env.generate_certificates()?;
    env.generate_test_data()?;
    env.create_pkcs7_files()?;
    
    println!("\nTest files preparation completed successfully!");
    println!("Generated files can be found in:");
    println!("- Certificates: {}", env.certs_dir.display());
    println!("- Test data: {}", env.data_dir.display());
    println!("- PKCS#7 files: {}", env.output_dir.display());
    
    Ok(())
}