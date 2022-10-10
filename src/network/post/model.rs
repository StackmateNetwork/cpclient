use crate::key::encryption::{self,key_hash256};
use crate::key::ec::{XOnlyPair,xonly_to_public_key};
use bitcoin::secp256k1::schnorr::Signature;
use bitcoin::secp256k1::{XOnlyPublicKey};
use serde::{Deserialize, Serialize};
use crate::util::e::{S5Error,ErrorKind};
use::std::str::FromStr;
use std::ffi::CString;
use std::os::raw::c_char;

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct LocalPostModel {
    pub id: String,
    pub genesis: u64,
    pub expiry: u64,
    pub owner: XOnlyPublicKey,
    pub post: Post,
}
impl LocalPostModel{
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
pub struct Post {
    pub to: Recipient,
    pub payload: Payload,
    pub checksum: String,
    pub signature : Signature,
}

impl Post{
    pub fn new(
        to: Recipient, 
        payload: Payload, 
        xonly_pair: XOnlyPair
    )->Self{
        let checksum_message = to.to_string() + ":" + &payload.to_string();
        let checksum = key_hash256(&checksum_message);
        Post {
            to,
            payload,
            checksum:checksum.clone(),
            signature: xonly_pair.schnorr_sign(&checksum).unwrap(),
        }
    }
    pub fn stringify(&self) -> Result<String, S5Error> {
        match serde_json::to_string(self) {
            Ok(result) => Ok(result),
            Err(_) => {
                Err(S5Error::new(ErrorKind::Internal, "Error stringifying Post"))
            }
        }
    }

    pub fn structify(stringified: &str) -> Result<Post, S5Error> {
        match serde_json::from_str(stringified) {
            Ok(result) => Ok(result),
            Err(_) => {
                Err(S5Error::new(ErrorKind::Internal, "Error stringifying Post"))
            }
        }
    }
    pub fn to_cypher(&self, encryption_key: String)->String{
        let cypher = encryption::cc20p1305_encrypt(&self.stringify().unwrap(), &encryption_key).unwrap();
        cypher
    }
}


#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum RecipientKind {
    Direct,
    Group,
}
// impl fmt::Display for RecipientKind {
//     fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
//         match self{
//             RecipientKind::Direct=>fmt.write_str("direct").unwrap(),
//             RecipientKind::Group=>fmt.write_str("group").unwrap(),
//         }
//         Ok(())
//     }
// }
impl ToString for RecipientKind {
    fn to_string(&self)->String{
        match self{
            RecipientKind::Direct=>"direct".to_string(),
            RecipientKind::Group=>"group".to_string()
        }
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Recipient {
    kind: RecipientKind,
    value: String,
}
impl Recipient {
    pub fn new(kind: RecipientKind, value: String)->Self{
       Recipient{
        kind,
        value
       }
    }
    pub fn to_string(&self)->String{
        format!("{}:{}",self.kind.to_string(), self.value)
    }
}
impl FromStr for Recipient{
    type Err = S5Error;

    fn from_str(s: &str)->Result<Self,Self::Err>{
        let parts: Vec<&str> = s.split(":").collect();
        if parts.len() != 2{
            Err(S5Error::new(ErrorKind::Input,"Bad Recipient str format. Must be format => \'kind:value\'"))
        }
        else{
            let kind = match parts[0].to_lowercase().as_str(){
                "direct"=>RecipientKind::Direct,
                "group"=>RecipientKind::Group,
                _=> return Err(S5Error::new(ErrorKind::Input,"Bad Recipient kind. Must be direct or group."))
            };
            let value = parts[1].to_string();
            Ok(Recipient::new(kind,value))
        }
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum PayloadKind {
    Message,
    Secret,
}
impl ToString for PayloadKind {
    fn to_string(&self)->String{
        match self{
            PayloadKind::Message=>"message".to_string(),
            PayloadKind::Secret=>"secret".to_string()
        }
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Payload {
    kind: PayloadKind,
    value: String,
}
impl Payload {
    pub fn new(kind: PayloadKind, value: String)->Self{
       Payload{
        kind,
        value
       }
    }
    pub fn to_string(&self)->String{
        format!("{}:{}",self.kind.to_string(), self.value)
    }
}
impl FromStr for Payload{
    type Err = S5Error;

    fn from_str(s: &str)->Result<Self,Self::Err>{
        let parts: Vec<&str> = s.split(":").collect();
        if parts.len() != 2{
            Err(S5Error::new(ErrorKind::Input,"Bad Payload str format. Must be format => \'kind:value\'"))
        }
        else{
            let kind = match parts[0].to_lowercase().as_str(){
                "message"=>PayloadKind::Message,
                "secret"=>PayloadKind::Secret,
                _=> return Err(S5Error::new(ErrorKind::Input,"Bad Payload kind. Must be message or secret."))
            };
            let value = parts[1].to_string();
            Ok(Payload::new(kind,value))
        }
    }
}


#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct DecryptionKey{
   pub decryption_key: String,
   pub receiver: XOnlyPublicKey
}
impl DecryptionKey{
    pub fn new(decryption_key: &str,receiver: XOnlyPublicKey)->DecryptionKey{
        DecryptionKey {
            decryption_key: decryption_key.to_string(),
            receiver
        }
    }

    pub fn make_for_many(me: XOnlyPair, recipients: Vec<XOnlyPublicKey>,encryption_key: String)->Result<Vec<DecryptionKey>,S5Error>{
        Ok(
            recipients.into_iter().map(|recipient|{
                let shared_secret = me.compute_shared_secret(xonly_to_public_key(recipient)).unwrap();
                let decryption_key = encryption::cc20p1305_encrypt(&encryption_key, &shared_secret).unwrap();
                DecryptionKey{
                    decryption_key: decryption_key,
                    receiver: recipient
                }
            }).collect()
        )
    }
}



#[cfg(test)]
mod tests {
    use super::*;
    use crate::key::seed;
    use crate::key::child;
    use crate::key::ec;
    use bitcoin::util::bip32::{ExtendedPrivKey};
    use bitcoin::network::constants::Network;
    use std::str::FromStr;

    #[test]
    fn test_post_mode() {
        let seed1 = seed::MasterKeySeed::generate(24, "", Network::Bitcoin).unwrap();
        let social_child1 = ExtendedPrivKey::from_str(&child::social_root(seed1.xprv.to_string(),0).unwrap()).unwrap();
        let xonly_pair1 = ec::XOnlyPair::from_xprv(social_child1);
        let seed2 = seed::MasterKeySeed::generate(24, "", Network::Bitcoin).unwrap();
        let social_child2 = ExtendedPrivKey::from_str(&child::social_root(seed2.xprv.to_string(),0).unwrap()).unwrap();
        let xonly_pair2 = ec::XOnlyPair::from_xprv(social_child2);

        let one_post = Post::new(
            Recipient::new(RecipientKind::Direct,xonly_pair2.pubkey.to_string()),
            Payload::new(PayloadKind::Message,"Hi".to_string()),
            xonly_pair1
        );
        println!("{:#?}",one_post.stringify());
    }
}