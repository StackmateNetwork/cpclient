use crate::util::e::{ErrorKind, S5Error};
use serde::{Deserialize, Serialize};

use ureq::{Proxy, AgentBuilder};
use crate::network::handler::{HttpHeader,HttpMethod,APIEndPoint,ServerStatusResponse, OwnedBy, sign_request};
use crate::network::post::model::{LocalPostModel, Post, DecryptionKey, DerivationIndex,AllPosts};
use bitcoin::util::bip32::ExtendedPrivKey;
use crate::key::encryption::{nonce,key_hash256,cc20p1305_decrypt};
use crate::key::child;
use crate::key::ec::{XOnlyPair,xonly_to_public_key};
use bitcoin::secp256k1::{XOnlyPublicKey};

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ServerPostRequest{
    expiry: u64,
    derivation_index: u32,
    cypher_json: String
}

impl ServerPostRequest{
    pub fn new(expiry: u64, derivation_index: u32, cypher_json: &str)->ServerPostRequest{
        ServerPostRequest {
            expiry,
            derivation_index,
            cypher_json: cypher_json.to_string()
        }
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ServerPostIdResponse{
    pub id: String
}
impl ServerPostIdResponse{
    pub fn structify(stringified: &str) -> Result<ServerPostIdResponse, S5Error> {
        match serde_json::from_str(stringified) {
            Ok(result) => Ok(result),
            Err(_) => {
                Err(S5Error::new(ErrorKind::Internal, "Error stringifying ServerPostIdResponse"))
            }
        }
    }
}

pub fn create(host: String, socks5: Option<u32>, key_pair: XOnlyPair, cpost_req: ServerPostRequest)->Result<String, S5Error>{
    let full_url = host + &APIEndPoint::Post(None).to_string();
    let nonce = nonce();
    let signature = sign_request(key_pair.clone(), HttpMethod::Put, APIEndPoint::Post(None), &nonce).unwrap();
    let proxy = if socks5.is_some(){ 
        Some(Proxy::new(&format!("socks5://localhost:{}",socks5.unwrap().to_string())).unwrap())
    }
    else{
        None
    };
    let agent = if proxy.is_some(){
        AgentBuilder::new()
        .proxy(proxy.unwrap())
        .build()
    }
    else{
        AgentBuilder::new()
        .build()
    };
    match agent.put(&full_url)
        .set(&HttpHeader::Signature.to_string(), &signature)
        .set(&HttpHeader::Pubkey.to_string(), &key_pair.pubkey.to_string())
        .set(&HttpHeader::Nonce.to_string(), &nonce)
        .send_json(cpost_req){
            Ok(response)=>  
                match ServerPostIdResponse::structify(&response.into_string().unwrap())
                {
                    Ok(result)=>{
                        Ok(result.id)
                    },
                    Err(e) =>{
                        Err(e)
                    }
                }            
            Err(e)=>{
                Err(S5Error::from_ureq(e))
            }
        }

}

pub fn remove(host: String, socks5: Option<u32>, key_pair: XOnlyPair, id: String)->Result<(), S5Error>{
    let full_url = host + &APIEndPoint::Post(Some(id.clone())).to_string();
    let nonce = nonce();
    let signature = sign_request(key_pair.clone(), HttpMethod::Delete, APIEndPoint::Post(Some(id)), &nonce).unwrap();
    let proxy = if socks5.is_some(){ 
        Some(Proxy::new(&format!("socks5://localhost:{}",socks5.unwrap().to_string())).unwrap())
    }
    else{
        None
    };
    let agent = if proxy.is_some(){
        AgentBuilder::new()
        .proxy(proxy.unwrap())
        .build()
    }
    else{
        AgentBuilder::new()
        .build()
    };
    match agent.delete(&full_url)
        .set(&HttpHeader::Signature.to_string(), &signature)
        .set(&HttpHeader::Pubkey.to_string(), &key_pair.pubkey.to_string())
        .set(&HttpHeader::Nonce.to_string(), &nonce)
        .call(){
            Ok(response)=> match ServerStatusResponse::structify(&response.into_string().unwrap())
            {
                Ok(result)=>{
                    if result.status {
                        Ok(())
                    }
                    else {
                        Err(S5Error::new(ErrorKind::Network, "Server returned a false status. This resource might already be removed."))
                    }
                },
                Err(e) =>{
                    Err(e)
                }
            },
            Err(e)=>{
                Err(S5Error::from_ureq(e))
            }
        }

}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ServerPostKeysRequest{
    post_id: String,
    decryption_keys: Vec<DecryptionKey>
}

impl ServerPostKeysRequest{
    pub fn new(post_id: &str, decryption_keys: Vec<DecryptionKey>)->ServerPostKeysRequest{
        ServerPostKeysRequest {
            post_id: post_id.to_string(),
            decryption_keys
        }
    }
}

pub fn keys(host: String, socks5: Option<u32>, key_pair: XOnlyPair, post_id: String, decryption_keys: Vec<DecryptionKey>)->Result<(), S5Error>{
    let full_url = host + &APIEndPoint::PostKeys.to_string();
    let nonce = nonce();
    let signature = sign_request(key_pair.clone(), HttpMethod::Put, APIEndPoint::PostKeys, &nonce).unwrap();
    let body = ServerPostKeysRequest::new(&post_id, decryption_keys);
    let proxy = if socks5.is_some(){ 
        Some(Proxy::new(&format!("socks5://localhost:{}",socks5.unwrap().to_string())).unwrap())
    }
    else{
        None
    };
    let agent = if proxy.is_some(){
        AgentBuilder::new()
        .proxy(proxy.unwrap())
        .build()
    }
    else{
        AgentBuilder::new()
        .build()
    };
    match agent.put(&full_url)
        .set(&HttpHeader::Signature.to_string(), &signature)
        .set(&HttpHeader::Pubkey.to_string(), &key_pair.pubkey.to_string())
        .set(&HttpHeader::Nonce.to_string(), &nonce)
        .send_json(body){
            Ok(response)=> match ServerStatusResponse::structify(&response.into_string().unwrap())
            {
                Ok(result)=>{
                    if result.status {
                        Ok(())
                    }
                    else {
                        Err(S5Error::new(ErrorKind::Network, "Server returned a false status. This resource might already be removed."))
                    }
                },
                Err(e) =>{
                    Err(e)
                }
            },
            Err(e)=>{
                Err(S5Error::from_ureq(e))
            }
        }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ServerPostModel{
    pub id: String,
    pub genesis: u64,
    pub expiry: u64,
    pub owner: XOnlyPublicKey,
    pub cypher_json: String,
    pub derivation_index: u32,
    pub decryption_key: Option<String>
}
impl ServerPostModel{
    pub fn decypher(
        &self,
        social_root: ExtendedPrivKey
    )->Result<LocalPostModel, S5Error>{
        let my_xonly_pair = XOnlyPair::from_xprv(social_root);

        // check if reponse owner is self or other
        if self.owner == my_xonly_pair.pubkey {
            let decryption_key_root = child::hex(social_root.to_string(), self.clone().derivation_index).unwrap();
            let decryption_key = key_hash256(&decryption_key_root);
            let plain_json_string = match cc20p1305_decrypt(&self.clone().cypher_json, &decryption_key){
                Ok(result)=>result,
                Err(_)=>return Err(S5Error::new(ErrorKind::Key, "Decryption Error"))
            };
            
            Ok(LocalPostModel{
                id: self.clone().id,
                genesis: self.genesis,
                expiry: self.expiry,
                owner:  self.owner,
                post: Post::structify(&plain_json_string).unwrap(),
            })
        }
        else {
            let shared_secret = my_xonly_pair.compute_shared_secret(xonly_to_public_key(self.clone().owner)).unwrap();
            let decryption_key = cc20p1305_decrypt(&self.clone().decryption_key.unwrap(), &shared_secret).unwrap_or("Bad Key".to_string());
            let plain_json_string = match cc20p1305_decrypt(&self.cypher_json, &decryption_key){
                Ok(result)=>result,
                Err(_)=>return Err(S5Error::new(ErrorKind::Key, "Decryption Error"))
            };
    
            Ok(LocalPostModel{
                id: self.clone().id,
                genesis: self.genesis,
                expiry: self.expiry,
                owner: self.owner,
                post: Post::structify(&plain_json_string).unwrap(),
            })
        }

    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ServerPostModelResponse{
    pub posts: Vec<ServerPostModel>
}
impl ServerPostModelResponse{
    pub fn structify(stringified: &str) -> Result<ServerPostModelResponse, S5Error> {
        match serde_json::from_str(stringified) {
            Ok(result) => Ok(result),
            Err(_) => {
                Err(S5Error::new(ErrorKind::Internal, "Error stringifying ServerPostModelResponse"))
            }
        }
    }
}

fn my_posts(host: String, socks5: Option<u32>, key_pair: XOnlyPair, filter: Option<u64>)->Result<Vec<ServerPostModel>, S5Error>{
    let filter = if filter.is_some(){"?genesis_filter=".to_string() + &filter.unwrap().to_string()}else{"".to_string()};
    let full_url = host.to_string() + &APIEndPoint::Posts(OwnedBy::Me).to_string() + &filter;
    let nonce = nonce();
    let signature = sign_request(key_pair.clone(), HttpMethod::Get, APIEndPoint::Posts(OwnedBy::Me), &nonce).unwrap();
    let proxy = if socks5.is_some(){ 
        Some(Proxy::new(&format!("socks5://localhost:{}",socks5.unwrap().to_string())).unwrap())
    }
    else{
        None
    };
    let agent = if proxy.is_some(){
        AgentBuilder::new()
        .proxy(proxy.unwrap())
        .build()
    }
    else{
        AgentBuilder::new()
        .build()
    };
    match agent.get(&full_url)
        .set(&HttpHeader::Signature.to_string(), &signature)
        .set(&HttpHeader::Pubkey.to_string(), &key_pair.pubkey.to_string())
        .set(&HttpHeader::Nonce.to_string(), &nonce)
        .call(){
            Ok(response)=> match ServerPostModelResponse::structify(&response.into_string().unwrap())
            {
                Ok(result)=>{
                    Ok(result.posts)
                },
                Err(e) =>{
                    Err(e)
                }
            },
            Err(e)=>{
                Err(S5Error::from_ureq(e))
            }
        }
}

fn others_posts(host: String, socks5: Option<u32>, key_pair: XOnlyPair, filter: Option<u64>)->Result<Vec<ServerPostModel>, S5Error>{
    let filter = if filter.is_some(){"?genesis_filter=".to_string() + &filter.unwrap().to_string()}else{"".to_string()};
    let full_url = host.to_string() + &APIEndPoint::Posts(OwnedBy::Others).to_string() + &filter;

    let nonce = nonce();
    let signature = sign_request(key_pair.clone(), HttpMethod::Get, APIEndPoint::Posts(OwnedBy::Others), &nonce).unwrap();
    let proxy = if socks5.is_some(){ 
        Some(Proxy::new(&format!("socks5://localhost:{}",socks5.unwrap().to_string())).unwrap())
    }
    else{
        None
    };
    let agent = if proxy.is_some(){
        AgentBuilder::new()
        .proxy(proxy.unwrap())
        .build()
    }
    else{
        AgentBuilder::new()
        .build()
    };
    match agent.get(&full_url)
        .set(&HttpHeader::Signature.to_string(), &signature)
        .set(&HttpHeader::Pubkey.to_string(), &key_pair.pubkey.to_string())
        .set(&HttpHeader::Nonce.to_string(), &nonce)
        .call(){
            Ok(response)=> match ServerPostModelResponse::structify(&response.into_string().unwrap())
            {
                Ok(result)=>{
                    Ok(result.posts)
                },
                Err(e) =>{
                    Err(e)
                }
            },
            Err(e)=>{
                Err(S5Error::from_ureq(e))
            }
        }
}

fn process_cypherposts(social_root: ExtendedPrivKey,posts: Vec<ServerPostModel>)->Result<AllPosts,S5Error>{
    let mut plains: Vec<LocalPostModel> = [].to_vec();
    for post in posts.into_iter(){
        match post.decypher(social_root){
            Ok(result)=>plains.push(result),
            Err(_)=>()
        }
    }
    Ok(AllPosts::new(plains))
}

pub fn get_all_posts(host: String, socks5: Option<u32>,  social_root: ExtendedPrivKey, filter: Option<u64>)->Result<AllPosts,S5Error>{
    let xonly_pair = XOnlyPair::from_xprv(social_root.clone());
    let mut all_posts = my_posts(host.clone(),socks5, xonly_pair.clone(), filter).unwrap();
    all_posts.append(&mut others_posts(host,socks5, xonly_pair, filter).unwrap());
    process_cypherposts(social_root, all_posts)
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ServerPostSingleResponse{
    pub post: ServerPostModel
}
impl ServerPostSingleResponse{
    pub fn structify(stringified: &str) -> Result<ServerPostSingleResponse, S5Error> {
        match serde_json::from_str(stringified) {
            Ok(result) => Ok(result),
            Err(_) => {
                Err(S5Error::new(ErrorKind::Internal, "Error stringifying ServerPostSingleResponse"))
            }
        }
    }
}

pub fn single_post(host: String, socks5: Option<u32>, xonly_pair: XOnlyPair,post_id: String)->Result<ServerPostModel, S5Error>{
    let full_url = host + &APIEndPoint::Post(Some(post_id.to_string())).to_string();
    let nonce = nonce();
    let signature = sign_request(xonly_pair.clone(), HttpMethod::Get, APIEndPoint::Post(Some(post_id.to_string())), &nonce).unwrap();
    let proxy = if socks5.is_some(){ 
        Some(Proxy::new(&format!("socks5://localhost:{}",socks5.unwrap().to_string())).unwrap())
    }
    else{
        None
    };
    let agent = if proxy.is_some(){
        AgentBuilder::new()
        .proxy(proxy.unwrap())
        .build()
    }
    else{
        AgentBuilder::new()
        .build()
    };
    match agent.get(&full_url)
        .set(&HttpHeader::Signature.to_string(), &signature)
        .set(&HttpHeader::Pubkey.to_string(), &xonly_pair.pubkey.to_string())
        .set(&HttpHeader::Nonce.to_string(), &nonce)
        .call(){
            Ok(response)=> match ServerPostSingleResponse::structify(&response.into_string().unwrap())
            {
                Ok(result)=>{
                    Ok(result.post)
                },
                Err(e) =>{
                    Err(e)
                }
            },
            Err(e)=>{
                Err(S5Error::from_ureq(e))
            }
        }
}


pub fn last_derivation(host: String, socks5: Option<u32>, xonly_pair: XOnlyPair)->Result<DerivationIndex, S5Error>{
    let full_url = host + &APIEndPoint::LastDerivation.to_string();
    let nonce = nonce();
    let signature = sign_request(xonly_pair.clone(), HttpMethod::Get, APIEndPoint::LastDerivation, &nonce).unwrap();
    let proxy = if socks5.is_some(){ 
        Some(Proxy::new(&format!("socks5://localhost:{}",socks5.unwrap().to_string())).unwrap())
    }
    else{
        None
    };
    let agent = if proxy.is_some(){
        AgentBuilder::new()
        .proxy(proxy.unwrap())
        .build()
    }
    else{
        AgentBuilder::new()
        .build()
    };
    match agent.get(&full_url)
        .set(&HttpHeader::Signature.to_string(), &signature)
        .set(&HttpHeader::Pubkey.to_string(), &xonly_pair.pubkey.to_string())
        .set(&HttpHeader::Nonce.to_string(), &nonce)
        .call(){
            Ok(response)=> match DerivationIndex::structify(&response.into_string().unwrap())
            {
                Ok(result)=>{
                    Ok(result)
                },
                Err(e) =>{
                    Err(e)
                }
            },
            Err(e)=>{
                Err(S5Error::from_ureq(e))
            }
        }
}


#[cfg(test)]
mod tests {
    use super::*;
    use crate::network::identity::dto::{admin_invite,user_invite,register,get_all};
    use crate::key::ec;
    use crate::key::seed;
    use crate::key::child;
    use crate::network::post::model::{Post,Payload,PayloadKind,Recipient,RecipientKind};
    use bitcoin::network::constants::Network;
    use crate::network::identity::model::{UserIdentity};
    use crate::network::handler::{InvitePermission};
    use bitcoin::util::bip32::{ExtendedPrivKey};
    use std::str::FromStr;
    #[test]
    #[ignore]
    fn test_post_dto(){
        let url = "http://localhost:3021".to_string();
        // ADMIN INVITE
        let admin_invite_code = "098f6bcd4621d373cade4e832627b4f6".to_string();
        let client_invite_code1 = admin_invite(url.clone(), None,admin_invite_code.clone(),InvitePermission::Standard).unwrap();
        assert_eq!(client_invite_code1.invite_code.len() , 32);

        let client_invite_code2 = admin_invite(url.clone(), None,admin_invite_code.clone(),InvitePermission::Privilege(1)).unwrap();
        assert_eq!(client_invite_code2.invite_code.len() , 32);

        // REGISTER USERS
        let nonce = nonce();

        let seed1 = seed::MasterKeySeed::generate(24, "", Network::Bitcoin).unwrap();
        let user1 = "builder".to_string() + &nonce[0..3];
        let social_child1 = ExtendedPrivKey::from_str(&child::social_root(seed1.xprv.to_string(),0).unwrap().xprv).unwrap();
        let my_identity = UserIdentity::new(social_child1.to_string()).unwrap();
        let xonly_pair1 = ec::XOnlyPair::from_xprv(my_identity.social_root);
        assert!(register(url.clone(), None, xonly_pair1.clone(), client_invite_code1.invite_code, user1).is_ok());
        
        let seed2 = seed::MasterKeySeed::generate(24, "", Network::Bitcoin).unwrap();
        let social_child2 = ExtendedPrivKey::from_str(&child::social_root(seed2.xprv.to_string(),0).unwrap().xprv).unwrap();
        let fac_identity = UserIdentity::new(social_child2.to_string()).unwrap();

        let xonly_pair2 = ec::XOnlyPair::from_xprv(social_child2);
        let user2 = "facilitator".to_string() + &nonce[0..3];
        assert!(register(url.clone(), None, xonly_pair2.clone(), client_invite_code2.invite_code.clone(), user2).is_ok());

        let client_invite_code3 = user_invite(url.clone(), None, xonly_pair2.clone(),client_invite_code2.invite_code.clone()).unwrap();
        assert_eq!(client_invite_code3.invite_code.len() , 32);

        let seed3 = seed::MasterKeySeed::generate(24, "", Network::Bitcoin).unwrap();
        let social_child3 = ExtendedPrivKey::from_str(&child::social_root(seed3.xprv.to_string(),0).unwrap().xprv).unwrap();
        let e_identity = UserIdentity::new(social_child3.to_string()).unwrap();

        let xonly_pair3 = ec::XOnlyPair::from_xprv(social_child3);
        let user3 = "escrow".to_string() + &nonce[0..3];
        assert!(register(url.clone(), None, xonly_pair3.clone(), client_invite_code3.invite_code, user3).is_ok());

        // GET ALL USERS
        let members = get_all(url.clone(), None,xonly_pair3.clone()).unwrap();
        let user_count = members.identities.len();
        assert!(user_count>0);

        // Create a struct to share as user1 to user3
        let message_to_share = Payload::new(PayloadKind::Message,"Hello :)".to_string());
        let post = Post::new(Recipient::new(RecipientKind::Direct,xonly_pair3.clone().pubkey.to_string()), message_to_share, xonly_pair1.clone()); 
        let index = 0;
        let encryption_key = my_identity.derive_encryption_key(index);
        let cypher_json = post.to_cypher(encryption_key.clone());
        let cpost_req = ServerPostRequest::new(0, index,&cypher_json);
        let post_id = create(url.clone(), None,xonly_pair1.clone(), cpost_req).unwrap();
        assert_eq!(post_id.len(), 24);
        let decrypkeys = DecryptionKey::make_for_many(xonly_pair1.clone(),[xonly_pair3.clone().pubkey].to_vec(), encryption_key).unwrap();
        assert!(keys(url.clone(), None, xonly_pair1.clone(), post_id.clone(),decrypkeys).is_ok());

        // Create a struct to share as user3 to user1
        let message_to_share = Payload::new(PayloadKind::Message,"Hi guy :)".to_string());
        let post = Post::new(Recipient::new(RecipientKind::Direct,xonly_pair1.clone().pubkey.to_string()), message_to_share, xonly_pair3.clone()); 
        let index = 0;
        let encryption_key = e_identity.derive_encryption_key(index);
        let cypher_json = post.to_cypher(encryption_key.clone());
        let cpost_req = ServerPostRequest::new(0, index,&cypher_json);
        let post_id = create(url.clone(), None,xonly_pair3.clone(), cpost_req).unwrap();
        assert_eq!(post_id.len(), 24);
        let decrypkeys = DecryptionKey::make_for_many(xonly_pair3.clone(),[xonly_pair1.clone().pubkey].to_vec(), encryption_key).unwrap();
        assert!(keys(url.clone(), None, xonly_pair3.clone(), post_id.clone(),decrypkeys).is_ok());

        // Create a struct to share as user2 to group
        let message_to_share = Payload::new(PayloadKind::Message,"hey fren :)".to_string());
        let group_id = "s5g91ffac3a6b9ac".to_string();
        let post = Post::new(Recipient::new(RecipientKind::Group,group_id), message_to_share, xonly_pair2.clone()); 
        let index = 0;
        let encryption_key = fac_identity.derive_encryption_key(index);
        let cypher_json = post.to_cypher(encryption_key.clone());
        let cpost_req = ServerPostRequest::new(0, index,&cypher_json);
        let post_id = create(url.clone(), None,xonly_pair2.clone(), cpost_req).unwrap();
        assert_eq!(post_id.len(), 24);
        let decrypkeys = DecryptionKey::make_for_many(xonly_pair2.clone(),[xonly_pair1.clone().pubkey,xonly_pair3.clone().pubkey].to_vec(), encryption_key).unwrap();
        assert!(keys(url.clone(), None, xonly_pair2.clone(), post_id.clone(),decrypkeys).is_ok());

        // Get posts & keys as user2
        let all = get_all_posts(url.clone(), None, social_child2.clone(), None).unwrap();
        assert_eq!(all.posts.len(),1);
        // Get posts & keys as user3
        let all = get_all_posts(url.clone(), None, social_child3.clone(), None).unwrap();
        assert_eq!(all.posts.len(),3);
        // Get posts as self
        let mut all = get_all_posts(url.clone(), None, my_identity.social_root, None).unwrap();
        assert_eq!(all.posts.len(),3);
        println!("{:#?}",all.to_all_posts_as_chat(xonly_pair1.pubkey));
        // Delete post
        assert!(remove(url.clone(), None,xonly_pair1.clone(), post_id.clone()).is_ok());
        // KEEP BUILDING!
    }
}