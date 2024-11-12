/*use alloy::{
    network::{EthereumWallet, TransactionBuilder},
    primitives::{Address, Bytes},
    providers::{Provider, ProviderBuilder},
    rpc::types::{TransactionRequest,Filter, Log},
    signers::local::PrivateKeySigner,
    sol,
};

use clap::Parser;
use url::Url;*/

pub mod pkcs7;
/*
// Arguments of the publisher CLI.
#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
pub struct Args {
    /// Ethereum chain ID
    //#[clap(long)]
    //chain_id: u64,

    /// Ethereum Node endpoint.
    #[clap(long, env)]
    eth_wallet_private_key: PrivateKeySigner,

    /// Ethereum Node endpoint.
    #[clap(long)]
    rpc_url: Url,

    /// Application's contract address on Ethereum
    #[clap(long)]
    contract: Address,

    /// The input to provide to the guest binary
    #[clap(long)]
    p7_path: String,

    //salt value, priveded as hex string
    #[clap(long)]
    salt: String,
}


pub fn parse_arguments() -> Args {
    Args::parse()
}*/