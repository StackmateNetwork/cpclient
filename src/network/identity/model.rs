use serde::{Deserialize, Serialize};
use bitcoin::secp256k1::{XOnlyPublicKey};
use bitcoin::util::bip32::ExtendedPrivKey;
use crate::key::encryption::{cc20p1305_encrypt,cc20p1305_decrypt};
use crate::util::e::{ErrorKind, S5Error};
use crate::key::ec::{XOnlyPair};
use crate::key::child;
use crate::key::encryption;
use std::str::FromStr;
use std::ffi::CString;
use std::os::raw::c_char;

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ServerIdentity{
    pub kind: String,
    pub name: String,
    pub pubkey : String,
}

impl ServerIdentity{
    pub fn structify(stringified: &str) -> Result<ServerIdentity, S5Error> {
        match serde_json::from_str(stringified) {
            Ok(result) => Ok(result),
            Err(_) => {
                Err(S5Error::new(ErrorKind::Internal, "Error structifying ServerIdentity"))
            }
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

}


#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Invitation{
    pub invite_code: String
}
impl Invitation{
    pub fn structify(stringified: &str) -> Result<Invitation, S5Error> {
        match serde_json::from_str(stringified) {
            Ok(result) => Ok(result),
            Err(_) => {
                Err(S5Error::new(ErrorKind::Internal, "Error stringifying Invitation"))
            }
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
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct MemberIdentity{
    pub username: String,
    pub pubkey: XOnlyPublicKey,
}
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Members{
    pub identities: Vec<MemberIdentity>
}

impl Members{
    pub fn structify(stringified: &str) -> Result<Members, S5Error> {
        match serde_json::from_str(stringified) {
            Ok(result) => Ok(result),
            Err(_) => {
                Err(S5Error::new(ErrorKind::Internal, "Error stringifying Members"))
            }
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
}


#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct UserIdentity{
    pub social_root: ExtendedPrivKey,
}

impl UserIdentity {
    pub fn new(social_root: String)->Result<Self,S5Error>{
        let social_root = match ExtendedPrivKey::from_str(&social_root){
            Ok(root)=>root,
            Err(_)=>return Err(S5Error::new(ErrorKind::Input, "Bad social root key string."))
        };
        Ok(UserIdentity{
            social_root,
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
    pub fn encrypt(&self, key: String)->String{
        cc20p1305_encrypt(&self.stringify().unwrap(), &key).unwrap()
    }
    pub fn decrypt(cipher: String, key: String)->Result<UserIdentity, S5Error>{
        let id = match cc20p1305_decrypt(&cipher, &key){
            Ok(value)=>value,
            Err(e)=>return Err(e)
        };

        Ok(UserIdentity::structify(&id).unwrap())
    }
    pub fn to_xonly_pair(&self)->XOnlyPair{
       XOnlyPair::from_xprv(self.clone().social_root)
    }
    pub fn derive_encryption_key(&self, index: u32)->String{
        let enc_source = child::hex(self.social_root.to_string(), index).unwrap();
        encryption::key_hash256(&enc_source)
    }
}

