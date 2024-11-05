# zkVM Methods

This directory contains the zkVM portion of RISC Zero application. 


## Guest
In the guest folder is defined the guest program (the one that gets proved)

`pkcs7_verify.rs` guest program receives the inputs needed for pkcs7 file verification from an unstrusted party (apps/).

Based on the verification result, it will throw an error or commit results to the journal (receiver_address, salted_CF, CA_public_key)


`pkcs7_verify.rs` implements both `rsa_verify` and `ecdsa_verify` using respectively `rsa::pkcs1v15 crate` and `k256::ecdsa crate`

Other cryptographic operations are performed by [RISC Zero Cryptography Acceleration] for a faster execution and less resources consuming proving.

## Build.rs
Generate an Image.ID for the guest program, used on-chain for proof verification


[RISC Zero Cryptography Acceleration]: https://dev.risczero.com/api/zkvm/acceleration