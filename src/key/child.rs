extern crate bip85;
use crate::util::e::{ErrorKind, S5Error};
use crate::key::ec;
use bip85::bitcoin::secp256k1::Secp256k1;
use bip85::bitcoin::util::bip32::ExtendedPrivKey;
use serde::{Deserialize, Serialize};
use std::ffi::CString;
use std::os::raw::c_char;
use std::str::FromStr;

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct SocialRoot {
    pub xprv: String,
    pub mnemonic: String,
    pub pubkey: String,
}

impl SocialRoot {
    pub fn new(xprv: String, mnemonic: String, pubkey: String) -> Self {
        SocialRoot { xprv, mnemonic, pubkey }
    }
    pub fn c_stringify(&self) -> *mut c_char {
        let stringified = match serde_json::to_string(self) {
            Ok(result) => result,
            Err(_) => {
                return CString::new("Error:JSON Stringify Failed. BAD NEWS! Contact Support.")
                    .unwrap()
                    .into_raw()
            }
        };
        CString::new(stringified).unwrap().into_raw()
    }
    pub fn structify(stringified: &str) -> Result<SocialRoot, S5Error> {
        match serde_json::from_str(stringified) {
            Ok(result) => Ok(result),
            Err(_) => Err(S5Error::new(
                ErrorKind::Internal,
                "Error structifying SocialRoot",
            )),
        }
    }
}

pub fn social_root(master_root: String, index: u32) -> Result<SocialRoot, S5Error> {
    let master_xprv = match ExtendedPrivKey::from_str(&master_root) {
        Ok(root) => root,
        Err(_) => {
            return Err(S5Error::new(
                ErrorKind::Input,
                "Bad master root key string.",
            ))
        }
    };
    let secp = Secp256k1::new();
    let social_menmonic = bip85::to_mnemonic(&secp, &master_xprv, 12, index).unwrap();

    let seed = social_menmonic.to_seed("");
    let social_root = match ExtendedPrivKey::new_master(bip85::bitcoin::Network::Bitcoin, &seed) {
        Ok(xprv) => xprv,
        Err(e) => return Err(S5Error::new(ErrorKind::Key, &e.to_string())),
    };
    let keypair = ec::keypair_from_xprv_str(&social_root.to_string())?;
    let xonly = ec::XOnlyPair::from_keypair(keypair);
 
    Ok(SocialRoot::new(
        social_root.to_string(),
        social_menmonic.to_string(),
        xonly.pubkey.to_string(),
    ))
}
pub fn mnemonic_12(master_root: String, index: u32) -> Result<String, S5Error> {
    let root = match ExtendedPrivKey::from_str(&master_root) {
        Ok(root) => root,
        Err(_) => {
            return Err(S5Error::new(
                ErrorKind::Input,
                "Bad master root key string.",
            ))
        }
    };
    let secp = Secp256k1::new();
    let mnemonic = bip85::to_mnemonic(&secp, &root, 12, index).unwrap();
    Ok(mnemonic.to_string())
}
pub fn hex(social_root: String, index: u32) -> Result<String, S5Error> {
    let root = match ExtendedPrivKey::from_str(&social_root) {
        Ok(root) => root,
        Err(_) => {
            return Err(S5Error::new(
                ErrorKind::Input,
                "Bad master root key string.",
            ))
        }
    };
    let secp = Secp256k1::new();
    let hex = bip85::to_hex(&secp, &root, 64, index).unwrap();
    Ok(hex::encode(hex))
}
pub fn secret_key(social_root: String, index: u32) -> Result<String, S5Error> {
    let root = match ExtendedPrivKey::from_str(&social_root) {
        Ok(root) => root,
        Err(_) => {
            return Err(S5Error::new(
                ErrorKind::Input,
                "Bad master root key string.",
            ))
        }
    };
    let secp = Secp256k1::new();
    let wif = bip85::to_wif(&secp, &root, index).unwrap();
    Ok(wif.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_social_root() {
        let master_xprv =
        "xprv9s21ZrQH143K2FJMh7DKFuDx9gNMjzA5BPA8NKkrmdF4p8fvpn5PUZsPKwGM1tydUQKQmYZXtgszJPKdiYXwyqAVSZCfRNpYZ7LVaeXJMdG";
        let social_xprv =
        "xprv9s21ZrQH143K4HgkGgtpYw9Ub8a8ZH33ZTeEJwAnyVvr91Zdkn3xbXxR8jo7Txu3tycENfX6k65SDsz7fS2dXsy5VCM6xLmVwS6ERRwu8rA";
        let social_mnemonic = "permit fuel media speak loud decline color street piano put nothing fog";
        let social_root = social_root(master_xprv.to_string(),0).unwrap();
        assert_eq!(social_root.xprv, social_xprv);
        assert_eq!(social_root.mnemonic, social_mnemonic);
    }
}
