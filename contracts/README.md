# Solidity Contracts

This directory contains the Solidity contracts and the [tests].


## CFWallet

Contains the function that receive the proof of the pkcs7 file validation.
```solidity
    function verifyAndTransfer(bytes calldata journal, bytes calldata seal) public {
        require(journal.length == 308, "Invalid journal length");

        // verify the proof
        verifier.verify(seal, imageId, sha256(journal));
        
        to = bytesToAddress(journal[0:20]);

        bytes32 extractedCf = bytes32(journal[20:52]);
        bytes calldata rootPubKey = journal[52:];

        bool is_journal_valid = verifyJournalData(extractedCf, rootPubKey);
        require(is_journal_valid, "Incorrect journal data");
        emit Log("Journal data verified");

        transfer(to);
    }
```

If the proof verification succed, the journal is decoded, retreiving the following values:

- `to`: ETH address. that the owner (Codice Fiscale owner) wants to send money.
- `extractedCf`: Hash of the salted CF (`keccak256(CF + salt)` ). It must be the same as the contract deployer, revert otherwise.
- `rootPubKey`: The public key of the Certification Authority that issues the user certificate. Check against the storage of [CA_Storage] contract.

## CA_Storage
Contract for the storage of the Certification Authority (CAs) public keys eIDAS compliant. 
Save the (keccack256 hashed) pubkeys in a mapping that only the owner of the contract can update.
```solidity
    mapping(bytes32 => bool) public publicKeys;
        
    function verifyPublicKey(bytes memory pubKey) external view returns (bool exists){
        bytes32 keyHash = keccak256(pubKey);
        return publicKeys[keyHash];
    }
```

`verifyPublicKey(bytes memory pubKey)` function used by CFWallet contract to verify the validity of the CA pubkey.

!!! Only one istance of this contract must be deployed.

!!! Currently only italian CA taked in consideration.

## Generated Contracts

When `cargo build` is runned, the `ImageID.sol` and `Elf.sol` contracts are generated, with up to date references to the [guest code].

- `ImageID.sol`: contains the [Image IDs] for the guests implemented in the [methods] directory.
- `Elf.sol`: contains the path of the guest binaries implemented in the [methods] directory.
  This contract is saved in the `tests` directory in the root of this template.

[tests]: ./tests/
[methods]: ../methods/README.md
[guest code]: ../methods/guest