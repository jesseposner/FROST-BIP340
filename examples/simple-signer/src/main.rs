use bitcoin::OutPoint;
use clap::{Parser, Subcommand};

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
            println!("Creating address");
        }
        Commands::SignTransaction {
            destination_address,
            spending_prevout,
        } => {
            println!("Signing transaction");
        }
    }
}
