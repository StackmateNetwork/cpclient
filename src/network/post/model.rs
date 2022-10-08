use crate::key::encryption::{self,key_hash256};
use crate::key::ec::{XOnlyPair,xonly_to_public_key};
use bdk::bitcoin::secp256k1::schnorr::Signature;
use bitcoin::secp256k1::{XOnlyPublicKey};
use serde::{Deserialize, Serialize};
use crate::util::e::{S5Error,ErrorKind};

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct LocalPostModel {
    pub id: String,
    pub genesis: u64,
    pub expiry: u64,
    pub owner: XOnlyPublicKey,
    pub post: Post,
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
        keypair: XOnlyPair
    )->Self{
        let checksum_message = to.to_string() + ":" + &payload.to_string();
        let checksum = key_hash256(&checksum_message);
        Post {
            to,
            payload,
            checksum:checksum.clone(),
            signature: keypair.schnorr_sign(&checksum).unwrap(),
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
pub enum Recipient {
    Direct(XOnlyPublicKey),
    Group(String),
}
impl Recipient {
    pub fn to_string(&self)->String{
        match self{
            Recipient::Direct(pubkey)=>pubkey.to_string(),
            Recipient::Group(id)=>id.to_string()
        }
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum Payload {
    Message(String),
}
impl Payload {
    pub fn to_string(&self)->String{
        match self{
            Payload::Message(text)=>text.to_string(),
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

