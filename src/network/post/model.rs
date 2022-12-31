use crate::key::encryption::{self,key_hash256};
use crate::key::ec::{XOnlyPair,xonly_to_public_key,schnorr_verify};
use bitcoin::secp256k1::schnorr::Signature;
use bitcoin::secp256k1::{XOnlyPublicKey};
use serde::{Deserialize, Serialize};
use crate::util::e::{S5Error,ErrorKind};
use::std::str::FromStr;
use std::ffi::CString;
use std::os::raw::c_char;
use std::collections::BTreeMap;

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct PostId {
    pub id: String,
}
impl PostId{
    pub fn new(id: String)->Self{
        PostId{
            id
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
    pub fn structify(stringified: &str) -> Result<PostId, S5Error> {
        match serde_json::from_str(stringified) {
            Ok(result) => Ok(result),
            Err(_) => {
                Err(S5Error::new(ErrorKind::Internal, "Error stringifying PostId"))
            }
        }
    }
}

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
    pub fn structify(stringified: &str) -> Result<LocalPostModel, S5Error> {
        match serde_json::from_str(stringified) {
            Ok(result) => Ok(result),
            Err(_) => {
                Err(S5Error::new(ErrorKind::Internal, "Error stringifying LocalPostModel"))
            }
        }
    }
    pub fn verify(&self)->Result<(),S5Error>{
      let checksum_message = self.post.to.to_string() + ":" + &self.post.payload.to_string();
      let checksum = key_hash256(&checksum_message);
      if checksum != self.post.checksum{
        Err(S5Error::new(ErrorKind::Post,"Checksum Mismatch! Cannot trust this message"))
      }
      else{
        schnorr_verify(self.post.signature, &self.post.checksum, self.owner)    
      } 
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct PostsAsChat{
    pub counter_party: String,
    pub posts: Vec<LocalPostModel>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct SortedPosts{
    pub verified: Vec<PostsAsChat>,
    pub corrupted: Vec<String>,
    pub latest_genesis: u64,

}

impl SortedPosts{
    pub fn default()->Self{
      SortedPosts{
        verified: [].to_vec(),
        corrupted: [].to_vec(),
        latest_genesis:0,
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
    pub fn structify(stringified: &str) -> Result<SortedPosts, S5Error> {
        match serde_json::from_str(stringified) {
            Ok(result) => Ok(result),
            Err(_) => {
                Err(S5Error::new(ErrorKind::Internal, "Error structifying SortedPosts"))
            }
        }
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct AllPosts {
    pub posts: Vec<LocalPostModel>
}
impl AllPosts{
    pub fn new(posts: Vec<LocalPostModel>)->Self{
        AllPosts{
            posts
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
    pub fn structify(stringified: &str) -> Result<AllPosts, S5Error> {
        match serde_json::from_str(stringified) {
            Ok(result) => Ok(result),
            Err(_) => {
                Err(S5Error::new(ErrorKind::Internal, "Error structifying AllPosts"))
            }
        }
    }
    pub fn to_all_posts_as_chat(&mut self, my_pubkey: XOnlyPublicKey)->SortedPosts{
        if self.posts.len() == 0 {
          SortedPosts::default();
        }
        // earliest first
        self.posts.sort_by_key(|post| post.genesis);
        let mut btree = BTreeMap::<String, Vec<LocalPostModel>>::new();
        let mut corrupted:Vec<String> = [].to_vec();
        for item in self.clone().posts.into_iter(){
            if item.clone().verify().is_ok(){
              let counter_party = match item.clone().post.to.kind{
                  RecipientKind::Direct=>{
                      if item.clone().owner == my_pubkey {
                          item.clone().post.to.value
                      }
                      else{
                          item.clone().owner.to_string()
                      }
                  }
                  RecipientKind::Group=>{
                      item.clone().post.to.value
                  }
              };

              if btree.contains_key(&counter_party){
                  btree.entry(counter_party).and_modify(|value| value.push(item));
              }
              else{
                  btree.insert(counter_party,[item].to_vec());
              }
            }
            else{
                corrupted.push(item.clone().id);
                ()
            }
        };
        let mut all_pas: Vec<PostsAsChat> = [].to_vec();
        for (key, value) in btree.iter() {
            all_pas.push(PostsAsChat{
                counter_party: key.to_string(),
                posts: value.clone(),
            });
        }
        SortedPosts{
            verified: all_pas,
            corrupted,
            latest_genesis:self.posts[self.posts.len() - 1].genesis,
        }
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
    pub kind: PayloadKind,
    pub value: String,
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

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct DerivationIndex{
    pub last_used: u32
}
impl DerivationIndex{
    pub fn structify(stringified: &str) -> Result<DerivationIndex, S5Error> {
        match serde_json::from_str(stringified) {
            Ok(result) => Ok(result),
            Err(_) => {
                Err(S5Error::new(ErrorKind::Internal, "Error stringifying DerivationIndex"))
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
        let social_child1 = ExtendedPrivKey::from_str(&child::social_root(seed1.xprv.to_string(),0).unwrap().xprv).unwrap();
        let xonly_pair1 = ec::XOnlyPair::from_xprv(social_child1);
        let seed2 = seed::MasterKeySeed::generate(24, "", Network::Bitcoin).unwrap();
        let social_child2 = ExtendedPrivKey::from_str(&child::social_root(seed2.xprv.to_string(),0).unwrap().xprv).unwrap();
        let xonly_pair2 = ec::XOnlyPair::from_xprv(social_child2);

        let one_post = Post::new(
            Recipient::new(RecipientKind::Direct,xonly_pair2.pubkey.to_string()),
            Payload::new(PayloadKind::Message,"Hi".to_string()),
            xonly_pair1
        );
        println!("{:#?}",one_post.stringify());
    }
}