use std::str::FromStr;

use bitcoin::{consensus::Encodable, hex::DisplayHex, OutPoint};
use clap::{Parser, Subcommand};
mod transaction;
use bitcoin::hex;

#[derive(Clone, Parser)]
#[clap()]
pub struct Cli {
    #[clap(subcommand)]
    command: Commands,
}

#[derive(Clone, Subcommand)]
enum Commands {
    CreateAddress {},
    SignTransaction {
        destination_address: String,
        spending_prevout: OutPoint,
    },
}

fn main() {
    let cli = Cli::parse();

    match cli.command {
        Commands::CreateAddress {} => {
            let agg_pk = bitcoin::PublicKey::from_slice(&[0;33]).unwrap();
            transaction::create_address(agg_pk);
        }
        Commands::SignTransaction {
            destination_address,
            spending_prevout,
        } => {
            let addr = bitcoin::Address::from_str(&destination_address).unwrap().assume_checked();
            let spending_utxo = bitcoin::TxOut {
                value: bitcoin::Amount::from_sat(100_000),
                script_pubkey: addr.script_pubkey(),
            };
            let signed_tx = transaction::sign_transaction(spending_prevout, spending_utxo, addr);
            let mut bytes = Vec::new();
            signed_tx.consensus_encode(&mut bytes).unwrap();
            println!("{}", bytes.to_hex_string(hex::Case::Lower));
        }
    }
}
