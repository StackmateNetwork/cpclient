use crate::lib::e::{S5Error,ErrorKind};
use crate::key::ec::{XOnlyPair};
use serde::{Deserialize, Serialize};
use std::str::FromStr;

pub enum HttpMethod{
    Get,
    Put,
    Post,
    Delete    
}

impl HttpMethod{
    pub fn to_string(&self)->String{
        match self{
            HttpMethod::Get=>"GET".to_string(),
            HttpMethod::Put=>"PUT".to_string(),
            HttpMethod::Post=>"POST".to_string(),
            HttpMethod::Delete=>"DELETE".to_string(),
        }
    }
}

pub enum HttpHeader{
    AdminInvite,
    ClientInvite,
    Pubkey,
    Signature,
    Nonce
}

impl HttpHeader{
    pub fn to_string(&self)->String{
        match self{
            HttpHeader::AdminInvite=>"x-admin-invite-secret".to_string(),
            HttpHeader::ClientInvite=>"x-client-invite-code".to_string(),
            HttpHeader::Pubkey=>"x-client-pubkey".to_string(),
            HttpHeader::Signature=>"x-client-signature".to_string(),
            HttpHeader::Nonce=>"x-nonce".to_string(),
        }
    }
}

pub enum APIEndPoint{
    AdminInvite,
    Identity,
    AllIdentities,
    Announce(AnnouncementType),
    Announcements(OwnedBy),
    Revoke(AnnouncementType),
    Post(Option<String>),
    Posts(OwnedBy),
    PostKeys,
    Notifications
}

pub enum OwnedBy{
    Me,
    Others
}
impl OwnedBy {
    pub fn to_string(&self)->String{
        match self{
            OwnedBy::Me=>"self".to_string(),
            OwnedBy::Others=>"others".to_string(),
        }
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum AnnouncementType{
    Trust,
    Scam,
    Escrow
}
impl AnnouncementType {
    pub fn to_string(&self)->String{
        match self{
            AnnouncementType::Trust=>"Trust".to_string(),
            AnnouncementType::Scam=>"Scam".to_string(),
            AnnouncementType::Escrow=>"Escrow".to_string(),
        }
    }
}
impl FromStr for AnnouncementType{
    type Err = S5Error;

    fn from_str(s: &str)->Result<Self,Self::Err>{
        Ok(
            match s{
                "Trust"=>AnnouncementType::Trust,
                "trust"=>AnnouncementType::Trust,
                "TRUST"=>AnnouncementType::Trust,
                "Escrow"=>AnnouncementType::Escrow,
                "escrow"=>AnnouncementType::Escrow,
                "ESCROW"=>AnnouncementType::Escrow,
                "Scam"=>AnnouncementType::Scam,
                "scam"=>AnnouncementType::Scam,
                "SCAM"=>AnnouncementType::Scam,
                _=>AnnouncementType::Scam
            }
        )
    }
}

impl APIEndPoint{
    pub fn to_string(&self)->String{
        match self{
            APIEndPoint::AdminInvite=>"/api/v2/identity/admin/invitation".to_string(),
            APIEndPoint::Identity=>"/api/v2/identity".to_string(),
            APIEndPoint::AllIdentities=>"/api/v2/identity/all".to_string(),
            APIEndPoint::Announce(kind)=>"/api/v2/announcement/".to_string() + &kind.to_string().to_lowercase(),
            APIEndPoint::Revoke(kind)=>"/api/v2/announcement/".to_string() + &kind.to_string().to_lowercase() + "/revoke",
            APIEndPoint::Announcements(owner)=>{
                match owner {
                    OwnedBy::Me=>"/api/v2/announcement/".to_string() + &owner.to_string(),
                    OwnedBy::Others=>"/api/v2/announcement/".to_string() + "all",
                }
            },
            APIEndPoint::Post(id)=>{
                match id {
                    Some(id)=>"/api/v2/post".to_string() + "/" + id,
                    None=>"/api/v2/post".to_string()
                }
            },
            APIEndPoint::Posts(owner)=>"/api/v2/post/".to_string() + &owner.to_string(),
            APIEndPoint::PostKeys=>"/api/v2/post/keys".to_string(),
            APIEndPoint::Notifications=>"/api/v3/notifications".to_string(),
        }
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ServerStatusResponse{
    pub status: bool
}
impl ServerStatusResponse{
    pub fn structify(stringified: &str) -> Result<ServerStatusResponse, S5Error> {
        match serde_json::from_str(stringified) {
            Ok(result) => Ok(result),
            Err(_) => {
                Err(S5Error::new(ErrorKind::Internal, "Error stringifying ServerStatusResponse"))
            }
        }
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ServerErrorResponse {
    pub code: i32,
    pub message: String,
}

impl ServerErrorResponse{
    pub fn structify(stringified: &str) -> Result<ServerErrorResponse, S5Error> {
        match serde_json::from_str(stringified) {
            Ok(result) => Ok(result),
            Err(_) => {
                Err(S5Error::new(ErrorKind::Internal, "Error stringifying ServerErrorResponse"))
            }
        }
    }
}

pub fn sign_request(keys: XOnlyPair, method: HttpMethod, endpoint: APIEndPoint, nonce: &str)-> Result<String, S5Error>{
    let message = method.to_string() + " " + &endpoint.to_string() + " " + nonce;
    let signature = keys.schnorr_sign(&message).unwrap();
    return Ok(signature.to_string());
}

// #[cfg(test)]
// mod tests {
//     use super::*;
//     use crate::key::ec;
//     use crate::key::seed;
//     use bitcoin::network::constants::Network;
//     use crate::cypherpost::model::{PostKind};
//     use secp256k1::rand::{thread_rng,Rng};
//     use crate::cypherpost::model::{PostItem};

//     #[test]
//     fn test_sign_cp_request(){
//         let seed = seed::generate(24, "", Network::Bitcoin).unwrap();
//         let key_pair = ec::keypair_from_xprv_str(&seed.xprv).unwrap();
//         let signature = sign_request(key_pair, HttpMethod::Get, APIEndPoint::AllIdentities, "56783999222311").unwrap();
//         let message = "GET /api/v2/identity/all 56783999222311";
//         let verification = ec::schnorr_verify(&signature, message , &key_pair.public_key().to_string()).unwrap();
//         assert!(verification);
//     }
//     #[test]
//     fn test_encrypt_decrypt(){
//         let social_root_scheme = "m/128h/0h";

//         let mut rng = thread_rng();
//         let random = rng.gen::<u64>();
//         let random_string = random.to_string();

//         let seed1 = seed::generate(24, "", Network::Bitcoin).unwrap();
//         let social_child1 = child::to_path_str(&seed1.xprv, social_root_scheme).unwrap();
//         let key_pair1 = ec::keypair_from_xprv_str(&social_child1.xprv).unwrap();
//         let xonly_pair1 = ec::XOnlyPair::from_keypair(key_pair1);

//         let message_1_to_2 = "hi there".to_string();
//         let post_1_to_2 = PlainPost::new(
//             PostKind::Message,
//             None,
//             PostItem::new(
//                 Some("msg".to_string()), message_1_to_2
//             )
//         );
    
//         let cp_1_to_2 = create_cypherjson(&social_child1.xprv, post_1_to_2.clone()).unwrap();

//         let seed2 = seed::generate(24, "", Network::Bitcoin).unwrap();
//         let social_child2 = child::to_path_str(&seed2.xprv, social_root_scheme).unwrap();
//         let key_pair2 = ec::keypair_from_xprv_str(&social_child2.xprv).unwrap();
//         let xonly_pair2 = ec::XOnlyPair::from_keypair(key_pair2);
//         let user2 = "facilitator".to_string() + &random_string[0..3];
//         let cp_id = CypherpostIdentity{
//             username: user2,
//             pubkey: xonly_pair2.clone().pubkey
//         };

//         let decryption_keys = create_decryption_keys(&social_child1.xprv, &cp_1_to_2.0,[cp_id].to_vec()).unwrap();

//         let cpmodel = cypherpost::model::CypherPostModel{
//             id: "not_important".to_string(),
//             genesis: 2389283,
//             expiry: 0,
//             owner: xonly_pair1.pubkey,
//             cypher_json: cp_1_to_2.1,
//             derivation_scheme: cp_1_to_2.0,
//             decryption_key: Some(decryption_keys.clone().pop().unwrap().decryption_key)
//         };

//         let plain_model = decrypt_others_posts([cpmodel].to_vec(), &social_child2.xprv).unwrap();

//         assert_eq!(plain_model.clone().pop().unwrap().plain_post.item.value,post_1_to_2.item.value);

//     }

// }