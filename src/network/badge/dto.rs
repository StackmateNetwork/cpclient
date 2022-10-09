use ureq::{Proxy, AgentBuilder};
use serde::{Deserialize, Serialize};

use crate::key::encryption::{nonce};
use crate::key::ec::{XOnlyPair};
use crate::network::handler::{HttpHeader,HttpMethod,APIEndPoint,OwnedBy,ServerStatusResponse, sign_request};
use crate::network::badge::model::{Badge};
use crate::util::e::{ErrorKind, S5Error};
use bitcoin::secp256k1::{XOnlyPublicKey};
use bdk::bitcoin::secp256k1::schnorr::Signature;

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct AnnouncementRequest{
    recipient: String,
    nonce: String, 
    signature: String
}
impl AnnouncementRequest{
    pub fn new(recipient: XOnlyPublicKey, nonce: String, signature: Signature)->AnnouncementRequest{
        AnnouncementRequest {
            recipient: recipient.to_string(),
            nonce: nonce,
            signature: signature.to_string()

        }
    }
}

pub fn announce(host: String, socks5: Option<u32>, keypair: XOnlyPair, badge: Badge)->Result<(), S5Error>{
    let full_url = host + &APIEndPoint::Announce(badge.clone().kind).to_string();
    let nonce = nonce();
    let signature = sign_request(keypair.clone(), HttpMethod::Post, APIEndPoint::Announce(badge.kind), &nonce).unwrap();
    let body = AnnouncementRequest::new(badge.to, badge.nonce, badge.signature);
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
    match agent.post(&full_url)
        .set(&HttpHeader::Signature.to_string(), &signature)
        .set(&HttpHeader::Pubkey.to_string(), &keypair.pubkey.to_string())
        .set(&HttpHeader::Nonce.to_string(), &nonce)
        .send_json(body){
            Ok(response)=>  
                match ServerStatusResponse::structify(&response.into_string().unwrap())
                {
                    Ok(result)=>{
                        if result.status {
                            Ok(())
                        }
                        else {
                            Err(S5Error::new(ErrorKind::Network, "Server returned a false status."))
                        }
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

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct AllBadgesResponse{
    pub announcements: Vec<Badge>
}

impl AllBadgesResponse{
    pub fn structify(stringified: &str) -> Result<AllBadgesResponse, S5Error> {
        match serde_json::from_str(stringified) {
            Ok(result) => Ok(result),
            Err(e) => {
                Err(S5Error::new(ErrorKind::Internal, &e.to_string()))
            }
        }
    }
}

pub fn get_all(host: String, socks5: Option<u32>, keypair: XOnlyPair)->Result<Vec<Badge>, S5Error>{
    let full_url = host + &APIEndPoint::Announcements(OwnedBy::Others).to_string();
    let nonce = nonce();
    let signature = sign_request(keypair.clone(), HttpMethod::Get, APIEndPoint::Announcements(OwnedBy::Others), &nonce).unwrap();
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
        .set(&HttpHeader::Pubkey.to_string(), &keypair.pubkey.to_string())
        .set(&HttpHeader::Nonce.to_string(), &nonce)
        .call(){
            Ok(response)=>{
                match AllBadgesResponse::structify(&response.into_string().unwrap())
                {
                    Ok(result)=>Ok(result.announcements),
                    Err(e) =>{
                        return Err(e)
                    }
                }
            }
            Err(e)=>{
                Err(S5Error::from_ureq(e))
            }
        }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct BadgeRevokeRequest{
    revoking: String,
}
impl BadgeRevokeRequest{
    pub fn new(revoking: XOnlyPublicKey)->BadgeRevokeRequest{
        BadgeRevokeRequest {
            revoking: revoking.to_string()
        }
    }
}
pub fn revoke(host: String, socks5: Option<u32>, keypair: XOnlyPair, badge: Badge)->Result<(), S5Error>{
    let full_url = host + &APIEndPoint::Revoke(badge.clone().kind).to_string();
    let nonce = nonce();
    let signature = sign_request(keypair.clone(), HttpMethod::Post, APIEndPoint::Revoke(badge.clone().kind), &nonce).unwrap();
    let body = BadgeRevokeRequest::new(badge.to);
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
    match agent.post(&full_url)
        .set(&HttpHeader::Signature.to_string(), &signature)
        .set(&HttpHeader::Pubkey.to_string(), &keypair.pubkey.to_string())
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::network::identity::dto::{admin_invite,register};
    use crate::key::ec;
    use crate::key::seed;
    use crate::key::child;
    use bdk::bitcoin::network::constants::Network;
    use crate::network::handler::{AnnouncementType};
    use crate::network::handler::{InvitePermission};
    use bdk::bitcoin::util::bip32::{ExtendedPrivKey};
    use std::str::FromStr;

    #[test]
    #[ignore]
    fn test_badges_dto(){
        let url = "http://localhost:3021".to_string();
        // ADMIN INVITE
        let admin_invite_code = "098f6bcd4621d373cade4e832627b4f6".to_string();
        let client_invite_code1 = admin_invite(url.clone(), None,admin_invite_code.clone(),InvitePermission::Standard).unwrap();
        assert_eq!(client_invite_code1.invite_code.len() , 32);
        
        let client_invite_code2 = admin_invite(url.clone(), None,admin_invite_code.clone(),InvitePermission::Standard).unwrap();
        assert_eq!(client_invite_code1.invite_code.len() , 32);

        // REGISTER USERS
        let nonce = nonce();

        let seed1 = seed::generate(24, "", Network::Bitcoin).unwrap();
        let social_child1 = ExtendedPrivKey::from_str(&child::social_root(seed1.xprv.to_string(),0).unwrap()).unwrap();
        let xonly_pair1 = ec::XOnlyPair::from_xprv(social_child1);
        let user1 = "builder".to_string() + &nonce[0..3];

        assert!(register(url.clone(), None, xonly_pair1.clone(), client_invite_code1.invite_code, user1).is_ok());
        
        let seed2 = seed::generate(24, "", Network::Bitcoin).unwrap();
        let social_child2 = ExtendedPrivKey::from_str(&child::social_root(seed2.xprv.to_string(),0).unwrap()).unwrap();
        let xonly_pair2 = ec::XOnlyPair::from_xprv(social_child2);
        let user2 = "facilitator".to_string() + &nonce[0..3];
        
        assert!(register(url.clone(), None, xonly_pair2.clone(), client_invite_code2.invite_code, user2).is_ok());

        let badge1to2 = Badge::new(AnnouncementType::Trust,xonly_pair1.clone(),xonly_pair2.pubkey);
        assert!(badge1to2.verify());

        assert!(announce(url.clone(), None, xonly_pair1.clone(), badge1to2.clone()).is_ok());

        let badges: Vec<Badge> = get_all(url.clone(), None, xonly_pair2.clone()).unwrap();
        let count = badges.len();
        assert!(count > 0);
        
        revoke(url.clone(), None, xonly_pair1.clone(), badge1to2.clone()).unwrap();
        
        let badges: Vec<Badge> = get_all(url.clone(), None, xonly_pair2).unwrap();
        let count_update = badges.len();
        assert!(count - count_update == 1);

    }
}