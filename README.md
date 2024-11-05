
# CF Wallet RISC ZERO

The project goal is to build an Ethereum application capable of manage a wallet using your own Codice Fiscale (tax ID code). The system uses [RISC Zero] as a coprocessor to the smart contract application, moving the computationally-intensive process off-chain in the zkVM, saving gas fees and maintaining core values of decentralization.

We can trust the off-chain computation thanks to verifiable computations granted by ZK technology that generates a proof about the correct execution of Rust code. With this proof, anyone can verify that the computation ran correctly and produced the associated outputs.


The zkVM generate a proof of correct eIDAS-compliant digital signature verification. Once the proof is generated (using [Bonsai])  it is sent to smart contract, that verifies it using RiscZeroVerifier contract. If the verification is successful, the contract will decode the journal (public outputs within the receipt) to confirm the following:

- The salted CF, ensuring that the user who owns the contract is the one invoke the fund transfer.
- The issuer of the user’s certificate is an eIDAS-compliant Certification Authority (CA).

If one of the verification fails, the smart contract will revert the transaction.

### Project component
- [Application] (Rust): Serves as the project’s entry point, parsing input, initiating proof requests to Bonsai, and posting proofs to the Ethereum contract.
- [zkVM Program] (Rust): Defines the computation to be proven, specifically for digital signature verification.
- [Contracts] (Solidity): Manages on-chain operations. CFwallet.sol contains the core application logic, while CA_Storage.sol securely stores the public key of the eIDAS-compliant Certification Authority (CA).

### Project structure
```bash
.
├── Cargo.toml                        # Configuration for Cargo and Rust
├── foundry.toml                      # Configuration for Foundry
├── apps
│   ├── Cargo.toml
│   └── src
│       └── bin                     
│           └── publisher.rs          # Logic of the application 
├── contracts
│   ├── src
│   │   ├── CFWallet.sol              # Contract that handle proof verification and transfer
│   │   ├── CA_Storage.sol            # Storage contract to keep trusted CA's public key
│   │   └── ImageID.sol               # Generated contract with the image ID for your zkVM program
│   └── tests
│       ├── CFWallet.t.sol            # Tests for the contracts
│       └── Elf.sol                   # Generated contract with paths the guest program ELF files.
│
├── core                              # Common module for shared structures
│   ├── Cargo.toml
│   └── src
│       └── parser.rs
│
├── methods
│   ├── Cargo.toml
│   ├── guest
│   │   ├── Cargo.toml
│   │   └── src
│   │       └── bin                 
│   │           └── pkcs7_verify.rs     # Guest program verifying a pkcs7 file
│   └── src
│       └── lib.rs                      # Compiled image IDs and tests for guest programs
│
└── script
    ├── Deploy.s.sol                    # Deploy CFWallet and RIscZeroVerifier
    ├── DeployCAStorage.s.sol           # Deploy CA_Storage
    ├── get_cakey.py                    # Get CA's pubkey from LOTL (EU lists of trusted list)
    └── config.toml
```

### Project flow
- ONLY ADMIN: deploy CA_Storage contract and update it with CA's public keys.

User usage guidelines:
- Deploy its own CF_Wallet contract providing his salted CF
- Sign a document including the content (-nodetached)
    - The document content MUST be the ETH address of the wallet to send money 
    - The subject field MUST be user Codice Fiscale
- Incapsulate the signed document in a pkcs7 file
- Run the program providing: 
    - wallet private key
    - node provider api_key
    - CF_Wallet contract address
    - path to pkcs7 file (`.p7m`,`.p7b`, or `p7s`)
    - salt used in contract creation phase


By doing this the user is able to send money in an authenticated way (thanks to eIDAS digital signature), without expose any of its data (thanks to zero knowledge proof) 

![Alt text](./risc0-foundry-template.png)


## Build the code

To run the project you have to install:
- Rust and [Foundry]
- rzup (needed to install cargo-risczero)
```bash
    curl -L https://risczero.com/install | bash
    rzup
```

- Builds for Rust code (app, zkVM) and Solidity smart contract
```bash
    cargo build
    forge build
```
- Configure bonsai api
```bash
    export BONSAI_API_KEY="YOUR_API_KEY" 
    export BONSAI_API_URL="BONSAI_URL" 
```
- Run test
```bash
    cargo test
    forge test -vvv
```

## Deploy
For a more specific instruction go to [RISC Zero Ethereum Deployment Guide]

Two possibilities of deploy:
- Deploy the projet to local network 
- Deploy to a real net

### Local network
1. Start a local testnet with `anvil` by running:

    ```bash
    anvil
    ```

    Once anvil is started, keep it running in the terminal, and switch to a new terminal.

2. Set your environment variables:
    > ***Note:*** You can generate your proofs locally, assuming you have a machine with an x86 architecture and [Docker] installed. In this case do not export Bonsai related env variables.

    ```bash
        # Anvil sets up a number of default wallets, and this private key is one of them.
        export ETH_WALLET_PRIVATE_KEY=0x... 
        export BONSAI_API_KEY="YOUR_API_KEY" 
        export BONSAI_API_URL="BONSAI_API_URL" 
    ```

3. Build your project:

    ```bash
    cargo build
    ```

4. Deploy the storage contract:
    ```bash
        # Private key of the CA_Storage contract owner
        export STORAGE_OWNER_KEY=0x...
        forge script --rpc-url http://localhost:8545 --broadcast script/DeployCAStorage.s.sol
    ```

> ### Warning
> skip this step, just for me (da modificare in futuro)
5. Get the eIDAS CA's public keys and update the storage state 
    ```bash
        # Get this address from the previous forge script command output
        export CA_STORAGE_ADDRESS=0x...
        python script/get_cakey.py

    ```

6. Deploy your contract by running:

    ```bash
        forge script --rpc-url http://localhost:8545 --broadcast script/Deploy.s.sol
    ```
This command should output something similar to:

    ```bash
    ...
    == Logs ==
    You are deploying on ChainID 31337
    Deployed RiscZeroGroth16Verifier to 0x5FbDB2315678afecb367f032d93F642f64180aa3
    Deployed CFWallet to 0xe7f1725E7734CE288F8367e1Bb143E90bb3F0512
    ...
    ```

Save the CfWallet contract address to the env variable:
    ```bash
        # Copy the address from the previous logs
        export EVEN_NUMBER_ADDRESS=0x...
    ```
7. Now you can interact with the contract

```bash
    # send ETH a CFWallet
    cast send ${} --value 1ether --rpc-url http://localhost:8545 --private-key ${ETH_WALLET_PRIVATE_KEY:?}
    
    # Get the balance of the contract
    cast balance ${EVEN_NUMBER_ADDRESS:?} --rpc-url http://localhost:8545

    # check receiver balance (debug purpose only)
    cast balance 0x71c7656ec7ab88b098defb751b7401b5f6d8976f --rpc-url http://localhost:8545
```
Publish a new state:
```bash

    cargo run -- --eth-wallet-private-key ${ETH_WALLET_PRIVATE_KEY:?} \
        --rpc-url http://localhost:8545 \
        --contract ${CFWALLET_ADDRESS:?} \
        --p7-path /path/to/your/pkcs7/file \
        --salt 01020304 
```

### Sepolia network

To deploy your contract to `Sepolia` testnet(or anyother network) you need to export your API_KEY ([Alchemy] as Ethereum node provider is used in this example):

    ```bash
        export ALCHEMY_API_KEY="YOUR_ALCHEMY_API_KEY"
        export ETH_WALLET_PRIVATE_KEY="YOUR_PRIVATE_KEY"
        export BONSAI_API_KEY="YOUR_API_KEY" 
        export BONSAI_API_URL="BONSAI_API_URL" 
    ```

Now the only difference from the local deployment is the --rpc-url parameter, from `http://localhost:8545` to `https://eth-sepolia.g.alchemy.com/v2/${ALCHEMY_API_KEY:?}`

So you can deploy CFWallet by running:
    ```bash
        forge script script/Deploy.s.sol --rpc-url https://eth-sepolia.g.alchemy.com/v2/${ALCHEMY_API_KEY:?} --broadcast
    ```

Do the same for all the other rpc call

## Project structure




[RISC Zero]: https://www.risczero.com/
[Bonsai]: https://risczero.com/bonsai
[Foundry]: https://book.getfoundry.sh/forge/
[Alchermy]: https://www.alchemy.com/

[RISC Zero Ethereum Deployment Guide]: ./deployment-guide.md
[Application]: ./app/
[zkVM Program]: ./methods/guest
[Contracts]: ./contracts/
