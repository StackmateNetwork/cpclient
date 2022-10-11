extern crate bip85;
use crate::util::e::{ErrorKind,S5Error};
use bip85::bitcoin::secp256k1::Secp256k1;
use bip85::bitcoin::util::bip32::{ExtendedPrivKey};
use std::str::FromStr;
use serde::{Deserialize, Serialize};
use std::ffi::CString;
use std::os::raw::c_char;


#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct SocialRoot {
  pub social_root: String,
}

impl SocialRoot {
    pub fn new(social_root:String)->Self{
        SocialRoot{
            social_root
        }
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
            Err(_) => {
                Err(S5Error::new(ErrorKind::Internal, "Error structifying SocialRoot"))
            }
        }
    }
}

pub fn social_root(master_root: String, index: u32) -> Result<String,S5Error>{
    let root = match ExtendedPrivKey::from_str(&master_root){
        Ok(root)=>root,
        Err(_)=>return Err(S5Error::new(ErrorKind::Input, "Bad master root key string."))
    };
    let secp = Secp256k1::new();
    let xprv = bip85::to_xprv(&secp, &root, index).unwrap();
    Ok(xprv.to_string())
}
pub fn mnemonic_12(master_root: String, index: u32) -> Result<String,S5Error>{
    let root = match ExtendedPrivKey::from_str(&master_root){
        Ok(root)=>root,
        Err(_)=>return Err(S5Error::new(ErrorKind::Input, "Bad master root key string."))
    };
    let secp = Secp256k1::new();
    let mnemonic = bip85::to_mnemonic(&secp, &root,12, index).unwrap();
    Ok(mnemonic.to_string())
}
pub fn hex(social_root: String, index: u32) -> Result<String,S5Error>{
    let root = match ExtendedPrivKey::from_str(&social_root){
        Ok(root)=>root,
        Err(_)=>return Err(S5Error::new(ErrorKind::Input, "Bad master root key string."))
    };
    let secp = Secp256k1::new();
    let hex = bip85::to_hex(&secp, &root, 64, index).unwrap();
    Ok(hex::encode(hex))
}
pub fn secret_key(social_root: String, index: u32) -> Result<String,S5Error>{
    let root = match ExtendedPrivKey::from_str(&social_root){
        Ok(root)=>root,
        Err(_)=>return Err(S5Error::new(ErrorKind::Input, "Bad master root key string."))
    };
    let secp = Secp256k1::new();
    let wif = bip85::to_wif(&secp, &root, index).unwrap();
    Ok(wif.to_string())
}

#[cfg(test)]
mod tests {
    // use super::*;
    #[test]
    fn test_derivation() {
        
    }

}
