use std::process::Command;

use bitcoin::hex::FromHex;
use bitcoin::secp256k1::schnorr;
use bitcoin::{taproot, Network};
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

pub fn sign_transaction(prevout: bitcoin::OutPoint, addr: bitcoin::Address) -> Transaction {
    let mut tx = Transaction {
        version: bitcoin::transaction::Version(2),
        lock_time: bitcoin::absolute::LockTime::from_height(2).unwrap(),
        input: vec![TxIn {
            previous_output: prevout,
            script_sig: ScriptBuf::new(),
            sequence: bitcoin::Sequence::MAX,
            witness: Witness::new(),
        }],
        output: vec![bitcoin::TxOut {
            value: bitcoin::Amount::from_sat(100_000),
            script_pubkey: addr.script_pubkey(),
        }],
    };

    // Call python code to get the signature
    let output = Command::new("python3")
                        .arg("/Users/sanketk/FROST-BIP340/examples/simple-signer/src/test.py")
                        .arg("msg")
                        .output()
                        .expect("Failed to execute command");

    let sig = if output.status.success() {
        let stdout = String::from_utf8_lossy(&output.stdout);
        taproot::Signature {
            signature: schnorr::Signature::from_slice(
                &Vec::<u8>::from_hex(&stdout).unwrap()
            ).unwrap(),
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

    use bitcoin::hashes::Hash;

    use super::sign_transaction;


    #[test]
    fn test_python_stdout() {
        let prevout = bitcoin::OutPoint {
            txid: bitcoin::Txid::from_byte_array([0; 32]),
            vout: 0,
        };
        let addr = bitcoin::Address::from_str("tb1pnzfn650wz5lptqttrhar64jycaf8tdy9gk69mud85dedww2lt3dsh73erq").unwrap();
        let addr_checked = addr.assume_checked();
        let tx = sign_transaction(prevout, addr_checked);
        let wit = tx.input[0].witness.to_vec();
        assert!(wit.len() > 0);
        assert!(wit[0].len() == 64);
    }
}