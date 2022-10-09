use serde::{Deserialize, Serialize};
use bitcoin::secp256k1::{XOnlyPublicKey};
use bdk::bitcoin::util::bip32::ExtendedPrivKey;
use crate::key::encryption::{cc20p1305_encrypt,cc20p1305_decrypt};
use crate::util::e::{ErrorKind, S5Error};
use crate::key::ec::{XOnlyPair};
use crate::key::child;
use crate::key::encryption;
use std::str::FromStr;

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct MemberIdentity{
    pub username: String,
    pub pubkey: XOnlyPublicKey,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct UserIdentity{
    pub social_root: ExtendedPrivKey,
    pub account: u32,
}

impl UserIdentity {
    pub fn new(social_root: String, account: u32)->Result<Self,S5Error>{
        let social_root = match ExtendedPrivKey::from_str(&social_root){
            Ok(root)=>root,
            Err(_)=>return Err(S5Error::new(ErrorKind::Input, "Bad social root key string."))
        };
        Ok(UserIdentity{
            social_root,
            account,
        })
    }
    pub fn stringify(&self) -> Result<String, S5Error> {
        match serde_json::to_string(self) {
            Ok(result) => Ok(result),
            Err(_) => {
                Err(S5Error::new(ErrorKind::Internal, "Error stringifying UserIdentity"))
            }
        }
    }
    pub fn structify(stringified: &str) -> Result<UserIdentity, S5Error> {
        match serde_json::from_str(stringified) {
            Ok(result) => Ok(result),
            Err(_) => {
                Err(S5Error::new(ErrorKind::Internal, "Error stringifying UserIdentity"))
            }
        }
    }
    pub fn encrypt(&self, password: String)->String{
        cc20p1305_encrypt(&self.stringify().unwrap(), &password).unwrap()
    }
    pub fn decrypt(cipher: String, password: String)->Result<UserIdentity, S5Error>{
        let id = match cc20p1305_decrypt(&cipher, &password){
            Ok(value)=>value,
            Err(e)=>return Err(e)
        };

        Ok(UserIdentity::structify(&id).unwrap())
    }
    pub fn to_xonly_pair(&self)->XOnlyPair{
       XOnlyPair::from_xprv(self.clone().social_root)
    }
    pub fn derive_encryption_key(&mut self, index: u32)->String{
        let enc_source = child::hex(self.social_root.to_string(), index).unwrap();
        encryption::key_hash256(&enc_source)
    }
}

