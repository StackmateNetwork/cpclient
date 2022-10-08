use serde::{Deserialize, Serialize};
use std::str::{FromStr};
use bdk::bitcoin::hashes::sha256;
use bdk::bitcoin::secp256k1::schnorr::Signature;
use bdk::bitcoin::secp256k1::Secp256k1;
use bitcoin::secp256k1::{ecdh::SharedSecret, KeyPair, Message, PublicKey, SecretKey, XOnlyPublicKey};
use bdk::bitcoin::util::bip32::ExtendedPrivKey;

use crate::lib::e::{ErrorKind, S5Error};

/// FFI Output
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct XOnlyPair {
  pub seckey: SecretKey,
  pub pubkey: XOnlyPublicKey,
}
impl XOnlyPair {
  pub fn from_keypair(keypair: KeyPair) -> XOnlyPair {
      let secp = Secp256k1::new();
      let public_key = PublicKey::from_keypair(&keypair);
      // ENFORCE EVEN PARITY!
      let parity = public_key.to_string().remove(1);
      let keypair = if parity == '3' {
        let mut seckey = SecretKey::from_keypair(&keypair);
        seckey.negate_assign();
        let key_pair = KeyPair::from_secret_key(&secp, seckey); 
        key_pair
      }
      else{
        keypair
      };
      return XOnlyPair {
        seckey: SecretKey::from_keypair(&keypair),
        pubkey: keypair.public_key(),
      };
  }
  pub fn from_xprv(xprv: ExtendedPrivKey) -> XOnlyPair {
    let secp = Secp256k1::new();
    let keypair = KeyPair::from_secret_key(&secp, xprv.private_key);
    let public_key = PublicKey::from_keypair(&keypair);
      // ENFORCE EVEN PARITY!
    let parity = public_key.to_string().remove(1);
    let keypair = if parity == '3' {
      let mut seckey = SecretKey::from_keypair(&keypair);
      seckey.negate_assign();
      let key_pair = KeyPair::from_secret_key(&secp, seckey); 
      key_pair
    }
    else{
      keypair
    };
    return XOnlyPair {
      seckey: SecretKey::from_keypair(&keypair),
      pubkey: keypair.public_key(),
    };
  }
  pub fn to_keypair(&self) -> KeyPair{
    let secp = Secp256k1::new();
    KeyPair::from_secret_key(&secp, self.seckey)
  }
  /// Generate a ecdsa shared secret
  pub fn compute_shared_secret(
    &self, 
    pubkey: PublicKey
  ) -> Result<String, S5Error> {
    let shared_secret = SharedSecret::new(&pubkey, &self.seckey);
    let shared_secret_hex = hex::encode(&(shared_secret.secret_bytes()));
    Ok(shared_secret_hex)
  }
  pub fn schnorr_sign(
    &self, 
    message: &str
  ) -> Result<Signature, S5Error> {
    let message = Message::from_hashed_data::<sha256::Hash>(message.as_bytes());
    let key_pair = self.to_keypair();
    let signature = key_pair.sign_schnorr(message);
    Ok(signature)
  }
}

pub fn xonly_to_public_key(xonly: XOnlyPublicKey) -> PublicKey{
  let pubkey = xonly.to_string();
  let public_key = if pubkey.len() == 64 {
    "02".to_string() + &pubkey
  } else {
    pubkey.to_string()
  };
  PublicKey::from_str(&public_key).unwrap()
}
pub fn schnorr_verify(signature: Signature,message: &str, pubkey: XOnlyPublicKey) -> Result<(), S5Error> {
  let message = Message::from_hashed_data::<sha256::Hash>(message.as_bytes());
  match signature.verify(&message, &pubkey) {
    Ok(_) => Ok(()),
    Err(_) => Err(S5Error::new(ErrorKind::Key, "BAD SIGNATURE"))
  }
}
pub fn keypair_from_xprv_str(xprv: &str) -> Result<KeyPair, S5Error> {
  let secp = Secp256k1::new();
  let xprv = match ExtendedPrivKey::from_str(xprv) {
    Ok(result) => result,
    Err(_) => return Err(S5Error::new(ErrorKind::Key, "BAD XPRV STRING")),
  };
  let key_pair = match KeyPair::from_seckey_str(&secp, &hex::encode(xprv.private_key.secret_bytes())) {
    Ok(kp) => kp,
    Err(_) => return Err(S5Error::new(ErrorKind::Key, "BAD SECKEY STRING")),
  };

  Ok(key_pair)
}
pub fn pubkey_from_str(
  pubkey: &str
) -> Result<XOnlyPublicKey,S5Error> {
  match XOnlyPublicKey::from_str(&pubkey) {
    Ok(pubkey) => Ok(pubkey),
    Err(_) =>  return Err(S5Error::new(ErrorKind::Key, "BAD PUBKEY STRING")),
  }
}
pub fn signature_from_str(sig_str: &str) -> Result<Signature, S5Error> {
  match Signature::from_str(sig_str) {
    Ok(sig) => return Ok(sig),
    Err(e) => return Err(S5Error::new(ErrorKind::Key, &e.to_string())),
  }
}


#[cfg(test)]
mod tests {
  use super::*;
  use crate::key::seed;
  use bdk::bitcoin::network::constants::Network;

  #[test]
  fn test_from_xprv_str() {
    let xprv= "xprv9ym1fn2sRJ6Am4z3cJkM4NoxFsaeNdSyFQvE5CqzqqterM5nZdKUStQghQWBupjAgJZEgAWCSQWuFgqbvdGwg22tiUp8rsupd4fTrtYMEWS";
    let key_pair = keypair_from_xprv_str(xprv).unwrap();
    let expected_pubkey = "86a4b6e8b4c544111a6736d4f4195027d23495d947f87aa448c088da477c1b5f";
    assert_eq!(expected_pubkey, key_pair.public_key().to_string());
  }

  #[test]
  fn test_schnorr_sigs() {
    let message = "stackmate 1646056571433";
    let seed = seed::generate(24, "", Network::Bitcoin).unwrap();
    let xonlypair = XOnlyPair::from_xprv(seed.xprv);
    let signature = xonlypair.schnorr_sign(message).unwrap();
    schnorr_verify(signature,message, xonlypair.pubkey).unwrap();
  }

  #[test]
  fn test_shared_secret() {
    let seed = seed::generate(24, "", Network::Bitcoin).unwrap();
    let alice_pair = XOnlyPair::from_xprv(seed.xprv);

    let seed = seed::generate(24, "", Network::Bitcoin).unwrap();
    let bob_pair = XOnlyPair::from_xprv(seed.xprv);
    // Alice only has Bob's XOnlyPubkey string
    let alice_shared_secret =
      alice_pair.compute_shared_secret(xonly_to_public_key(bob_pair.pubkey)).unwrap();
    // Bob only has Alice's XOnlyPubkey string
    let bob_shared_secret =
      bob_pair.compute_shared_secret(xonly_to_public_key(alice_pair.pubkey)).unwrap();
    assert_eq!(alice_shared_secret, bob_shared_secret);
  }
}