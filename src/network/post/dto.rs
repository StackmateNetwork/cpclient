use crate::lib::e::{ErrorKind, S5Error};
use serde::{Deserialize, Serialize};

use ureq;
use crate::network::handler::{HttpHeader,HttpMethod,APIEndPoint,ServerStatusResponse, OwnedBy, sign_request};
use crate::network::post::model::{LocalPostModel, Post, DecryptionKey};
use bdk::bitcoin::util::bip32::ExtendedPrivKey;
use crate::key::encryption::{nonce,key_hash256,cc20p1305_decrypt};
use crate::key::child;
use crate::key::ec::{XOnlyPair,xonly_to_public_key};
use bitcoin::secp256k1::{XOnlyPublicKey};

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ServerPostRequest{
    expiry: u64,
    derivation_scheme: String,
    cypher_json: String
}

impl ServerPostRequest{
    pub fn new(expiry: u64, derivation_scheme: &str, cypher_json: &str)->ServerPostRequest{
        ServerPostRequest {
            expiry,
            derivation_scheme: derivation_scheme.to_string(),
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

pub fn create(host: &str,key_pair: XOnlyPair, cpost_req: ServerPostRequest)->Result<String, S5Error>{
    let full_url = host.to_string() + &APIEndPoint::Post(None).to_string();
    let nonce = nonce();
    let signature = sign_request(key_pair.clone(), HttpMethod::Put, APIEndPoint::Post(None), &nonce).unwrap();
    
    match ureq::put(&full_url)
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

pub fn remove(host: &str,key_pair: XOnlyPair, id: &str)->Result<(), S5Error>{
    let full_url = host.to_string() + &APIEndPoint::Post(Some(id.to_string())).to_string();
    let nonce = nonce();
    let signature = sign_request(key_pair.clone(), HttpMethod::Delete, APIEndPoint::Post(Some(id.to_string())), &nonce).unwrap();

    match ureq::delete(&full_url)
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

pub fn keys(host: &str,key_pair: XOnlyPair, post_id: &str, decryption_keys: Vec<DecryptionKey>)->Result<(), S5Error>{
    let full_url = host.to_string() + &APIEndPoint::PostKeys.to_string();
    let nonce = nonce();
    let signature = sign_request(key_pair.clone(), HttpMethod::Put, APIEndPoint::PostKeys, &nonce).unwrap();
    let body = ServerPostKeysRequest::new(post_id, decryption_keys);

    match ureq::put(&full_url)
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
    pub derivation_scheme: String,
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
            let decryption_key_root = child::to_path_str(social_root, &self.clone().derivation_scheme).unwrap();
            let decryption_key = key_hash256(&decryption_key_root.xprv.to_string());
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

fn my_posts(host: &str,key_pair: XOnlyPair, filter: Option<u64>)->Result<Vec<ServerPostModel>, S5Error>{
    let filter = if filter.is_some(){"?genesis_filter=".to_string() + &filter.unwrap().to_string()}else{"".to_string()};
    let full_url = host.to_string() + &APIEndPoint::Posts(OwnedBy::Me).to_string() + &filter;
    let nonce = nonce();
    let signature = sign_request(key_pair.clone(), HttpMethod::Get, APIEndPoint::Post(Some("self".to_string())), &nonce).unwrap();
    match ureq::get(&full_url)
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

fn others_posts(host: &str,key_pair: XOnlyPair, filter: Option<u64>)->Result<Vec<ServerPostModel>, S5Error>{
    let filter = if filter.is_some(){"?genesis_filter=".to_string() + &filter.unwrap().to_string()}else{"".to_string()};
    let full_url = host.to_string() + &APIEndPoint::Posts(OwnedBy::Others).to_string() + &filter;

    let nonce = nonce();
    let signature = sign_request(key_pair.clone(), HttpMethod::Get, APIEndPoint::Post(Some("others".to_string())), &nonce).unwrap();

    match ureq::get(&full_url)
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

fn process_cypherposts(social_root: ExtendedPrivKey,posts: Vec<ServerPostModel>)->Result<Vec<LocalPostModel>,S5Error>{
    let mut plains = posts.into_iter().map(
        |post| {
            post.decypher(social_root).unwrap()
        }
    ).collect::<Vec<LocalPostModel>>();
    plains.sort_by_key(|post| post.genesis);
    Ok(plains)
}

pub fn get_all_posts(host: &str, social_root: ExtendedPrivKey, filter: Option<u64>)->Result<Vec<LocalPostModel>,S5Error>{
    let xonly_pair = XOnlyPair::from_xprv(social_root.clone());
    let mut all_posts = my_posts(host, xonly_pair.clone(), filter).unwrap();
    all_posts.append(&mut others_posts(host, xonly_pair, filter).unwrap());
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

pub fn single_post(host: &str,key_pair: XOnlyPair,post_id: &str)->Result<ServerPostModel, S5Error>{
    let full_url = host.to_string() + &APIEndPoint::Post(Some(post_id.to_string())).to_string();
    let nonce = nonce();
    let signature = sign_request(key_pair.clone(), HttpMethod::Get, APIEndPoint::Post(Some(post_id.to_string())), &nonce).unwrap();

    match ureq::get(&full_url)
        .set(&HttpHeader::Signature.to_string(), &signature)
        .set(&HttpHeader::Pubkey.to_string(), &key_pair.pubkey.to_string())
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


#[cfg(test)]
mod tests {
    use super::*;
    use crate::network::identity::dto::{admin_invite,register,get_all};
    use crate::key::ec;
    use crate::key::seed;
    use crate::key::child;
    use crate::network::post::model::{Post,Payload,Recipient};
    use bdk::bitcoin::network::constants::Network;
    use crate::network::identity::model::{UserIdentity};

    #[test]
    #[ignore]
    fn test_post_dto(){
        let url = "http://localhost:3021";
        // ADMIN INVITE
        let admin_invite_code = "098f6bcd4621d373cade4e832627b4f6";
        let client_invite_code1 = admin_invite(url,admin_invite_code).unwrap();
        assert_eq!(client_invite_code1.len() , 32);
        
        let client_invite_code2 = admin_invite(url,admin_invite_code).unwrap();
        assert_eq!(client_invite_code1.len() , 32);

        let client_invite_code3 = admin_invite(url,admin_invite_code).unwrap();
        assert_eq!(client_invite_code1.len() , 32);

        // REGISTER USERS
        let social_root_scheme = "m/128h/0h";

        let nonce = nonce();

        let seed1 = seed::generate(24, "", Network::Bitcoin).unwrap();
        let user1 = "builder".to_string() + &nonce[0..3];
        let mut my_identity = UserIdentity::new(user1.clone(),0,seed1.xprv);
        let xonly_pair1 = ec::XOnlyPair::from_xprv(my_identity.social_root);

        assert!(register(url, xonly_pair1.clone(), &client_invite_code1, &user1).is_ok());
        
        let seed2 = seed::generate(24, "", Network::Bitcoin).unwrap();
        let social_child2 = child::to_path_str(seed2.xprv, social_root_scheme).unwrap();
        let xonly_pair2 = ec::XOnlyPair::from_xprv(social_child2.xprv);
        let user2 = "facilitator".to_string() + &nonce[0..3];
        
        assert!(register(url, xonly_pair2.clone(), &client_invite_code2, &user2).is_ok());

        let seed3 = seed::generate(24, "", Network::Bitcoin).unwrap();
        let social_child3 = child::to_path_str(seed3.xprv, social_root_scheme).unwrap();
        let xonly_pair3 = ec::XOnlyPair::from_xprv(social_child3.xprv);
        let user3 = "escrow".to_string() + &nonce[0..3];
        
        assert!(register(url, xonly_pair3.clone(), &client_invite_code3, &user3).is_ok());

        // GET ALL USERS
        let identities = get_all(url,xonly_pair3.clone()).unwrap();
        let user_count = identities.len();
        assert!(user_count>0);

        // Create a struct to share
        let message_to_share = Payload::Message("Hello :)".to_string());
        let post = Post::new(Recipient::Direct(xonly_pair3.clone().pubkey), message_to_share, xonly_pair1.clone()); 
        let encryption_key = my_identity.derive_encryption_key();
        println!("{encryption_key}");
        let cypher_json = post.to_cypher(encryption_key.clone());
        let cpost_req = ServerPostRequest::new(0, &my_identity.last_path,&cypher_json);
        let post_id = create(url,xonly_pair1.clone(), cpost_req).unwrap();
        assert_eq!(post_id.len(), 24);
        let decrypkeys = DecryptionKey::make_for_many(xonly_pair1.clone(),[xonly_pair2.clone().pubkey,xonly_pair3.clone().pubkey].to_vec(), encryption_key).unwrap();
        assert!(keys(url, xonly_pair1.clone(), &post_id,decrypkeys).is_ok());
        // Get posts & keys as user2
        let posts = get_all_posts(url, social_child2.xprv, None).unwrap();
        assert_eq!(posts.len(),1);
        // Get posts & keys as user3
        let posts = get_all_posts(url, social_child3.xprv, None).unwrap();
        assert_eq!(posts.len(),1);
        // // Get posts as self
        let posts = get_all_posts(url, my_identity.social_root, None).unwrap();
        assert_eq!(posts.len(),1);
        // Delete post
        assert!(remove(url,xonly_pair1.clone(), &post_id).is_ok());
        // KEEP BUILDING!

    }
}