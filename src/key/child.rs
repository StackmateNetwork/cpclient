extern crate bip85;
use crate::util::e::{ErrorKind,S5Error};
use bip85::bitcoin::secp256k1::Secp256k1;
use bip85::bitcoin::util::bip32::{ExtendedPrivKey, ExtendedPubKey};
use std::str::FromStr;

pub fn check_xpub(xpub: &str) -> bool {
    ExtendedPubKey::from_str(xpub).is_ok()
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
    use super::*;

    #[test]
    fn test_derivation() {

    }

}
