use std::process::Command;
use std::str::FromStr;

use bitcoin::hex::FromHex;
use bitcoin::secp256k1::schnorr::Signature;
use bitcoin::secp256k1::{self, schnorr};
use bitcoin::sighash::SighashCache;
use bitcoin::{taproot, Network, TxOut};
/// Create a dummy transaction to spned from
///
use bitcoin::{
    key::TweakedPublicKey, Address, ScriptBuf, Transaction,
    TxIn, Witness, XOnlyPublicKey,
};

pub fn create_address(agg_pk: bitcoin::PublicKey) -> Address {
    let x_only_pk = TweakedPublicKey::dangerous_assume_tweaked(XOnlyPublicKey::from(agg_pk));
    Address::p2tr_tweaked(x_only_pk, Network::Testnet)
}

pub fn sign_transaction(prevout: bitcoin::OutPoint, spent_utxo: TxOut, addr: bitcoin::Address) -> Transaction {
    let mut tx = Transaction {
        version: bitcoin::transaction::Version(2),
        lock_time: bitcoin::absolute::LockTime::from_height(2).unwrap(),
        input: vec![TxIn {
            previous_output: prevout.clone(),
            script_sig: ScriptBuf::new(),
            sequence: bitcoin::Sequence::MAX,
            witness: Witness::new(),
        }],
        output: vec![bitcoin::TxOut {
            value: bitcoin::Amount::from_sat(99_000_000),
            script_pubkey: addr.script_pubkey(),
        }],
    };
    // Compute the sighash
    let binding = vec![spent_utxo];
    let prevouts = bitcoin::sighash::Prevouts::All(
        &binding,
    );
    let mut sighash = SighashCache::new(tx.clone());
    let msg = sighash.taproot_key_spend_signature_hash(0, &prevouts, bitcoin::TapSighashType::Default).unwrap();

    // Call python code to get the signature
    println!("msg: {}", msg.to_string());
    let output = Command::new("python3")
                        .arg("/Users/sanketk/FROST-BIP340/examples/simple-signer/src/test.py")
                        .arg(msg.to_string())
                        .output()
                        .expect("Failed to execute command");

    let sig = if output.status.success() {
        // let stdout = String::from_utf8_lossy(&output.stdout);
        // taproot::Signature {
        //     signature: schnorr::Signature::from_slice(
        //         &Vec::<u8>::from_hex(&stdout).unwrap()
        //     ).unwrap(),
        //     sighash_type: bitcoin::TapSighashType::Default,
        // }

        let secp = secp256k1::Secp256k1::new();
        let priv_key = bitcoin::PrivateKey::from_wif("KyJZEoRfDrAPVJVkNw1k4kFUNA2vDcrfxhn1yx9Gtrk7MCNWwbtv").unwrap();
        let keypair = secp256k1::Keypair::from_secret_key(&secp, &priv_key.inner);
        taproot::Signature {
            signature : Signature::from_str("9c323bab18cdaf67658d267e585a424bfe882151a3132e8452e1c4c23a4ade72a203022b630dd125bc732fa7fa78e661a09de57517e7ae9686a568575a43a71c").unwrap(),
            sighash_type: bitcoin::TapSighashType::Default,
        }
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr);
        panic!("Python script failed with error: {}", stderr);
    };

    tx.input[0].witness = Witness::p2tr_key_spend(&sig);
    tx
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use bitcoin::{consensus::{encode, Encodable}, hashes::Hash, hex::DisplayHex, key::TweakedPublicKey, XOnlyPublicKey};

    use super::sign_transaction;


    #[test]
    fn test_python_stdout() {
        let prevout = bitcoin::OutPoint {
            txid: bitcoin::Txid::from_str("a2615fa137ee4d121ed313df60f0b922cfffa2919b04e82757b49cdd14752cb6").unwrap(),
            vout: 1,
        };
        let addr = bitcoin::Address::from_str("bcrt1p58kucg5jzx8v6wd0hjvgf03aw6vryde4wva8ewazpdv6g3kd24qsa74rsv").unwrap();
        let addr_checked = addr.assume_checked();
        let spending_utxo = bitcoin::TxOut {
            value: bitcoin::Amount::from_sat(100_000_000),
            script_pubkey: addr_checked.script_pubkey(),
        };
        let tx = sign_transaction(prevout, spending_utxo, addr_checked);
        let wit = tx.input[0].witness.to_vec();
        assert!(wit.len() > 0);
        assert!(wit[0].len() == 64);
    }

    #[test]
    fn test_setup() {
        let secp = bitcoin::secp256k1::Secp256k1::new();
        let priv_key = bitcoin::PrivateKey::from_wif("KyJZEoRfDrAPVJVkNw1k4kFUNA2vDcrfxhn1yx9Gtrk7MCNWwbtv").unwrap();
        let pub_key = bitcoin::PublicKey::from_private_key(&secp, &priv_key);
        let pub_key = XOnlyPublicKey::from_str("a1edcc2292118ecd39afbc9884be3d7698323735733a7cbba20b59a446cd5541").unwrap();
        let tweaked_key = TweakedPublicKey::dangerous_assume_tweaked(XOnlyPublicKey::from(pub_key));
        let addr = bitcoin::Address::p2tr_tweaked(tweaked_key, bitcoin::Network::Regtest);
        println!("Address: {}", addr);

        let prevout = bitcoin::OutPoint {
            txid: bitcoin::Txid::from_str("a2615fa137ee4d121ed313df60f0b922cfffa2919b04e82757b49cdd14752cb6").unwrap(),
            vout: 1,
        };
        let spent_utxo = bitcoin::TxOut {
            value: bitcoin::Amount::from_sat(3_900),
            script_pubkey: addr.script_pubkey(),
        };

        let tx = sign_transaction(prevout, spent_utxo, addr);
        let bytes = encode::serialize(&tx);
        println!("{}", bytes.to_hex_string(bitcoin::hex::Case::Lower));
    }


}