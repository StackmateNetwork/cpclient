use serde::{Deserialize, Serialize};
use bip39::{Language, Mnemonic};
use bdk::bitcoin::network::constants::Network;
use bdk::bitcoin::secp256k1::rand::rngs::OsRng;
use bdk::bitcoin::secp256k1::Secp256k1;
use bdk::bitcoin::util::bip32::{ExtendedPrivKey};
use crate::key::encryption::{cc20p1305_encrypt,cc20p1305_decrypt};
use crate::lib::e::{ErrorKind, S5Error};

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct MasterKeySeed {
  pub fingerprint: String,
  pub mnemonic: Mnemonic,
  pub xprv: ExtendedPrivKey,
}
impl MasterKeySeed{

  pub fn stringify(&self) -> Result<String, S5Error> {
    match serde_json::to_string(self) {
        Ok(result) => Ok(result),
        Err(_) => {
            Err(S5Error::new(ErrorKind::Internal, "Error stringifying MasterKeySeed"))
        }
    }
  }
  pub fn structify(stringified: &str) -> Result<MasterKeySeed, S5Error> {
      match serde_json::from_str(stringified) {
          Ok(result) => Ok(result),
          Err(_) => {
              Err(S5Error::new(ErrorKind::Internal, "Error stringifying MasterKeySeed"))
          }
      }
  }
  pub fn encrypt(self, password: &str)->String{
    cc20p1305_encrypt(&self.stringify().unwrap(), &password).unwrap()
  }
  pub fn decrypt(cipher: String, password: String)->Result<MasterKeySeed,S5Error>{
    let master = match cc20p1305_decrypt(&cipher, &password){
      Ok(value)=>value,
      Err(e)=>return Err(e)
    };
    Ok(MasterKeySeed::structify(&master).unwrap())
  }
}

pub fn generate(
    length: usize, 
    passphrase: &str, 
    network: Network
  ) -> Result<MasterKeySeed, S5Error> {
    let secp = Secp256k1::new();
    let length: usize = if length == 12 || length == 24 {
      length
    } else {
      24
    };
    let mut rng = match OsRng::new() {
      Ok(r) => r,
      Err(e) => return Err(S5Error::new(ErrorKind::Key, &e.to_string())),
    };
    let mnemonic = match Mnemonic::generate_in_with(&mut rng, Language::English, length) {
      Ok(mne) => mne,
      Err(e) => return Err(S5Error::new(ErrorKind::Key, &e.to_string())),
    };
    let mnemonic_struct = match Mnemonic::parse_in(Language::English, &mnemonic.to_string()) {
      Ok(mne) => mne,
      Err(e) => return Err(S5Error::new(ErrorKind::Key, &e.to_string())),
    };
    let seed = mnemonic_struct.to_seed(passphrase);
    let master_xprv = match ExtendedPrivKey::new_master(network, &seed) {
      Ok(xprv) => xprv,
      Err(e) => return Err(S5Error::new(ErrorKind::Key, &e.to_string())),
    };
  
    Ok(MasterKeySeed {
      fingerprint: master_xprv.fingerprint(&secp).to_string(),
      mnemonic: mnemonic,
      xprv: master_xprv,
    })
  }

  pub fn import(
    mnemonic: &str, 
    passphrase: &str, 
    network: Network
  ) -> Result<MasterKeySeed, S5Error> {
    let secp = Secp256k1::new();
    let mnemonic_struct = match Mnemonic::parse_in(Language::English, mnemonic.to_string()) {
      Ok(mne) => mne,
      Err(e) => return Err(S5Error::new(ErrorKind::Key, &e.to_string())),
    };
    let seed = mnemonic_struct.to_seed(passphrase);
    let master_xprv = match ExtendedPrivKey::new_master(network, &seed) {
      Ok(xprv) => xprv,
      Err(e) => return Err(S5Error::new(ErrorKind::Key, &e.to_string())),
    };
  
    Ok(MasterKeySeed {
      fingerprint: master_xprv.fingerprint(&secp).to_string(),
      mnemonic: mnemonic_struct,
      xprv: master_xprv,
    })
  }

#[cfg(test)]
mod tests {
  use super::*;
  #[test]
  fn test_key_ops() {
    let master_key = generate(9, "password", Network::Testnet).unwrap();
    assert_eq!(
      24,
      master_key
        .mnemonic.to_string()
        .split_whitespace()
        .collect::<Vec<&str>>()
        .len()
    );
    let master_key = generate(12, "password", Network::Testnet).unwrap();
    assert_eq!(
      12,
      master_key
        .mnemonic.to_string()
        .split_whitespace()
        .collect::<Vec<&str>>()
        .len()
    );
    let master_key = generate(29, "password", Network::Testnet).unwrap();
    assert_eq!(
      24,
      master_key
        .mnemonic.to_string()
        .split_whitespace()
        .collect::<Vec<&str>>()
        .len()
    );
    let imported_master_key = import(&master_key.mnemonic.to_string(), "password", Network::Testnet).unwrap();
    assert_eq!(imported_master_key.xprv, master_key.xprv);
    assert_eq!(imported_master_key.fingerprint, master_key.fingerprint);
  }

  #[test]
  fn test_key_errors() {
    let invalid_mnemonic = "sushi dog road bed cliff thirty five four nine";
    let imported_key = import(invalid_mnemonic, "password", Network::Testnet)
      .err()
      .unwrap();
    let expected_emessage = "mnemonic has a word count that is not a multiple of 6: 9";
    assert_eq!(expected_emessage, imported_key.message);

    let invalid_mnemonic = "beach dog road bed cliff thirty five four nine ten eleven tweleve";
    let imported_key = import(invalid_mnemonic, "password", Network::Testnet)
      .err()
      .unwrap();
    let expected_emessage = "mnemonic contains an unknown word (word 3)";
    assert_eq!(expected_emessage, imported_key.message);
  }
}