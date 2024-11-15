//use k256::ecdsa::{Signature, signature::Verifier,  VerifyingKey};

use hex;
use k256::ecdsa::{
    signature::Verifier, Signature as EcdsaSignature, VerifyingKey as EcdsaVerifyingKey,
};

use crypto_bigint::U2048;
use crypto_bigint::Encoding;
/*use crypto_bigint::U64;
use crypto_bigint::NonZero;
use crypto_bigint::modular::runtime_mod::DynResidue;
use crypto_bigint::modular::runtime_mod::DynResidueParams;
use crypto_bigint::Encoding;*/
use k256::sha2::{Sha256};
use k256::sha2::Digest;
use risc0_zkvm::guest::env;
use rsa::{pkcs1v15::{Signature as RsaSignature, VerifyingKey as RsaVerifyingKey}, RsaPublicKey,};
use rsa::signature::DigestVerifier;

use tiny_keccak::{Hasher, Keccak};

use pkcs7_core::pkcs7::{CertificateData, CrlData, PublicKey};

const ECONTENT_MAX_LEN: usize = 128;
const SALT_MAX_LEN: usize = 16;
const MSG_MAX_LEN: usize = 256;
//const ALGO_OID_MAX_LEN: usize = 9;
const SIGNATURE_MAX_LEN: usize = 256;
const PUBKEY_MOD_MAX_LEN: usize = 256;
const PUBKEY_EXP_MAX_LEN: usize = 4;

// 3 bytes oid + 0x0c + len (quando estraggo cf len=0x10)
const CN_OID_BYTES: &[u8] = &[0x55, 0x04, 0x03, 0x0c, 0x10];

fn keccak256(bytes: &[u8], salt: &[u8]) -> [u8; 32] {
    let mut digest = [0u8; 32];
    let mut hasher = Keccak::v256();
    hasher.update(bytes);
    hasher.update(salt);
    hasher.finalize(&mut digest);
    digest
}

fn verify_rsa(modulus_bytes: &[u8], exp_bytes: &[u8], signature_bytes: &[u8], msg: &[u8]) -> bool {
    
    let modulus = rsa::BigUint::from_bytes_be(modulus_bytes);
    let exponent = rsa::BigUint::from_bytes_be(exp_bytes);

    let pub_key = match RsaPublicKey::new(modulus, exponent) {
        Ok(key) => key,
        Err(_) => return false,
    };

    let verifying_key = RsaVerifyingKey::<Sha256>::new(pub_key);

    let signature = match RsaSignature::try_from(signature_bytes) {
        Ok(sig) => sig,
        Err(_) => return false,
    };

    let mut hasher = Sha256::new();
    hasher.update(&msg);
    //verifying_key.verify(msg, &signature).is_ok()
    verifying_key.verify_digest(hasher,&signature).is_ok()
}


fn verify_ecdsa(
    key_bytes: &[u8],
    signature_bytes: &[u8],
    msg: &[u8],
) -> bool {
    if key_bytes.len() != 33 && key_bytes.len() != 65 {
        println!("error");
    }

    let verifying_key = EcdsaVerifyingKey::from_sec1_bytes(key_bytes).expect("failed to create verifying_key");
    let signature = EcdsaSignature::from_slice(&signature_bytes).unwrap();
    println!("-------------\nverkey {:?}\nsignature {:?}",verifying_key,signature);

    let res = verifying_key.verify(&msg, &signature).is_ok();
    println!("\nres: {:?}",res);
    res
}

fn verify_period(nbefore: u64, nafter: u64, now: u64) -> bool {
    nbefore <= now && nafter >= now
    
}



fn is_cert_revoked(cert: &CertificateData, crls: &[CrlData], now: u64) -> bool {
    for crl in crls {
        // check if CRL matches the certificate's issuer
        if crl.issuer == cert.issuer {
            // check if CRL is valid
            if !verify_period(crl.this_update, crl.next_update.unwrap_or(u64::MAX), now) {
                continue; // skip expired/invalid CRL
            }

            // verify CRL signature
            let is_valid = match &crl.issuer_pk {
                PublicKey::Rsa { modulus, exponent } => {
                    verify_rsa(modulus, exponent, &crl.signature, &crl.tbs_bytes)
                }
                PublicKey::Ecdsa { point } => {
                    verify_ecdsa(point, &crl.signature, &crl.tbs_bytes)
                }
            };
            if !is_valid {
                continue; //skip invalid signature
            }
            // check if certificate is revoked
            if crl.revoked_serials.contains(&cert.serial_number) {
                return true; 
            }
        }
    }
    false
}



fn verify_chain<'a>(chain: &'a [CertificateData], crls: &'a [CrlData], now: u64) -> &'a [u8] {
    let mut root_pk: &[u8] = &[];
    chain.iter().all(|cert| match &cert.issuer_pk {


        
        PublicKey::Rsa { modulus, exponent } => {
            let mut period_valid: bool = false;
            if cert.subject == cert.issuer {
                root_pk = modulus.as_ref();
            }
            // verify certificate revocation status
            if is_cert_revoked(cert, crls, now){
                return false;
            }
            assert!(verify_period(cert.not_before, cert.not_after, now));           
            verify_rsa(modulus, exponent, &cert.signature, &cert.tbs_bytes)
        }
        PublicKey::Ecdsa { point } => {
            let mut period_valid: bool = false;
            if cert.subject == cert.issuer {
                root_pk = point.as_ref();
            }
            if is_cert_revoked(cert, crls, now){
                return false;
            }
            assert!(verify_period(cert.not_before, cert.not_after, now));
            verify_ecdsa(point, &cert.signature, &cert.tbs_bytes)
            
        }
    });
    root_pk
}

// brutal function to extract cf
// TODO: verificare se è meglio cosi, o passare il cf al guest code
fn extract_cf_field(subject: &[u8]) -> Result<&[u8], &'static str> {
    // Find the position of the sequence in the subject
    if let Some(pos) = subject
        .windows(CN_OID_BYTES.len())
        .position(|window| window == CN_OID_BYTES)
    {
        // Calculate the start index of the field (after the OID sequence)
        let start = pos + CN_OID_BYTES.len();
        // Ensure there are enough bytes remaining
        if subject.len() >= start + 16 {
            // Extract the 16 bytes following the sequence
            return Ok(&subject[start..start + 16]);
        } else {
            return Err("Not enough bytes after OID sequence");
        }
    }
    Err("OID sequence not found in subject")
}


fn read_effective_slice(buf: &mut [u8], len: usize) -> &[u8] {
    env::read_slice(&mut buf[..len]);
    &buf[..len]
}


fn main() {
    let start = env::cycle_count();

    let cert_chain: Vec<CertificateData> = env::read();
    let crl_data: Vec<CrlData> = env::read();
    let now: u64 = env::read();
    let (
        econtent_len,
        salt_len,
        msg_len,
        //algoid_len,
        signature_len,
        pubkey_mod_len,
        pubkey_exp_len,
    ): (usize, usize, usize, usize, usize, usize) = env::read();

    assert!(econtent_len <= ECONTENT_MAX_LEN);
    assert!(salt_len <= SALT_MAX_LEN);
    assert!(msg_len <= MSG_MAX_LEN);
    //assert!(algoid_len <= ALGO_OID_MAX_LEN);
    assert!(signature_len <= SIGNATURE_MAX_LEN);
    assert!(pubkey_mod_len <= PUBKEY_MOD_MAX_LEN);
    assert!(pubkey_exp_len <= PUBKEY_EXP_MAX_LEN);

    // allocate fixed size array (stack)
    let mut econtent = [0u8; ECONTENT_MAX_LEN];
    let mut salt = [0u8; SALT_MAX_LEN];
    let mut msg = [0u8; MSG_MAX_LEN];
    //let mut algo_oid = [0u8; ALGO_OID_MAX_LEN];
    let mut signature = [0u8; SIGNATURE_MAX_LEN];
    let mut pubkey_mod = [0u8; PUBKEY_MOD_MAX_LEN];
    let mut pubkey_exp = [0u8; PUBKEY_EXP_MAX_LEN];

    // helper function to read and slice data
    let econtent = read_effective_slice(&mut econtent, econtent_len);
    let salt = read_effective_slice(&mut salt, salt_len);
    let msg = read_effective_slice(&mut msg, msg_len);
    let signature = read_effective_slice(&mut signature, signature_len);
    let pubkey_mod = read_effective_slice(&mut pubkey_mod, pubkey_mod_len);
    let pubkey_exp = read_effective_slice(&mut pubkey_exp, pubkey_exp_len);


    //let mut pubkey_exp: Vec<u8> = vec![0; pubkey_exp_len];
    //env::read_slice(&mut pubkey_exp);
    /* CHECK FOR DIFFERENT DIGEST ALGORITHM
    let digest = match algo_oid.as_slice() {
        // OID for SHA-1
        /*[0x2B, 0x0E, 0x03, 0x02, 0x1A] => {
            //let mut hasher = Sha1::new();
            //hasher.update(&msg);
            //hasher.finalize().to_vec()

        },*/
        // OID for SHA-256
        [0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01] => {
            let mut hasher = Sha256::new();
            hasher.update(&msg);
            hasher.finalize().as_slice()
        },
        _ => panic!("Unsupported digest algorithm OID"),
    };*/
    /*let mut hasher = ksha256::new();
    hasher.update(&msg);
    let digest = hasher.finalize();
    println!("\n[*] calculated digest on msg: {:?}\nresult: {:?}",msg, digest);

    let res: bool = verify_rsa_signature(
        &pubkey_mod,
        &pubkey_exp,
        &signature,
        &digest );*/


    assert!(
        verify_rsa(&pubkey_mod, &pubkey_exp, &signature, &msg),
        "Signature is not valid!"
    );

    // verify RSA or ECDSA
    /*let is_signature_valid = if let Some(exp) = pubkey_exp {
        //println!("[guest - main] Sending to verify_rsa:\npubkey_mod: {:?}\nsignature: {:?}\nmsg: {:?}",pubkey_mod,signature,hex::encode(&msg));
        verify_rsa(&pubkey_mod, &exp, &signature, &msg)
    }
    else {
        //println!("[guest - main] Sending to verify_ecdsa:\npubkey: {:?}\n\nsignature: {:?}\n\nmsg: {:?}",hex::encode(&pubkey_mod),hex::encode(&signature),hex::encode(&digest));
        verify_ecdsa(&pubkey_mod, &signature, &msg)

    };*/

    let trusted_pk = verify_chain(&cert_chain, &crl_data, now);
    let subject = &cert_chain[0].subject;
    let common_name = extract_cf_field(subject).expect("failed to extract common_name field value");

    let salted_cf = keccak256(common_name, salt);
    println!("\nsaltedCF: {:?}",hex::encode(&salted_cf));

    /*
        COMMIT:
            - address/msg (se commit solo address so che è lungo esattamente 42 caratteri)
            - hash (cf+salt) = 32 byte
            - root pk = tutto il resto (solitamente 256 byte)
    */
    //let fake_journal: &[u8] = &[0u8; 308];
    //println!("\nfake journal: {:?}",fake_journal);
    assert!(!trusted_pk.is_empty(), "Certificate chain is not valid!");
    //println!("\nguest. committing data:\necontent (eth address): {:?}\nsalted cf: {:?}\ntrusted_pk: {:?}",hex::encode(&econtent),hex::encode(&salted_cf), hex::encode(&trusted_pk));
    env::commit_slice(&econtent); //20 byte eth address (_to)
    env::commit_slice(&salted_cf); //32 byte
    env::commit_slice(trusted_pk);
    //env::commit_slice(fake_journal);
    let end = env::cycle_count();
    println!("my_operation_to_measure: {}", end - start);
}
