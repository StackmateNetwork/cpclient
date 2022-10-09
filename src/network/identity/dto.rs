use serde::{Deserialize, Serialize};
use std::ffi::CString;
use std::os::raw::c_char;

use ureq::{Proxy, AgentBuilder};

use crate::key::encryption::{nonce};
use crate::key::ec::{XOnlyPair};
use crate::network::handler::{HttpHeader,HttpMethod,APIEndPoint, InvitePermission, ServerStatusResponse, sign_request};
use crate::network::identity::model::{MemberIdentity};
use crate::util::e::{ErrorKind, S5Error};

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ServerIdentityResponse{
    pub name: String,
    pub pubkey: String,
}

impl ServerIdentityResponse{
    pub fn structify(stringified: &str) -> Result<ServerIdentityResponse, S5Error> {
        match serde_json::from_str(stringified) {
            Ok(result) => Ok(result),
            Err(_) => {
                Err(S5Error::new(ErrorKind::Internal, "Error stringifying ServerIdentityResponse"))
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

pub fn get_server_id(host: &str,socks5: Option<u32>, xonly_pair: XOnlyPair)->Result<ServerIdentityResponse, S5Error>{
    let full_url = host.to_string() + &APIEndPoint::ServerIdentity.to_string();
    let nonce = nonce();
    let signature = sign_request(xonly_pair.clone(), HttpMethod::Get, APIEndPoint::ServerIdentity, &nonce).unwrap();
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
            Ok(response)=>
                match ServerIdentityResponse::structify(&response.into_string().unwrap())
                {
                    Ok(result)=>Ok(result),
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
pub struct AdminInviteResponse{
    pub invite_code: String
}
impl AdminInviteResponse{
    pub fn structify(stringified: &str) -> Result<AdminInviteResponse, S5Error> {
        match serde_json::from_str(stringified) {
            Ok(result) => Ok(result),
            Err(_) => {
                Err(S5Error::new(ErrorKind::Internal, "Error stringifying AdminInviteResponse"))
            }
        }
    }
}
pub fn admin_invite(host: &str,socks5: Option<u32>, admin_secret: &str, permission: InvitePermission)->Result<String, S5Error>{
    let full_url = host.to_string() + &APIEndPoint::AdminInvite(permission).to_string();
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
        .set(&HttpHeader::AdminInvite.to_string(), admin_secret)
        .call()
        {
            Ok(response)=>  Ok(
                match AdminInviteResponse::structify(&response.into_string().unwrap()){
                    Ok(result)=>result.invite_code,
                    Err(e) =>{
                        return Err(e);
                    }
                }
            ),
            Err(e)=>{
                return Err(S5Error::from_ureq(e))
            }
        }
}

pub fn user_invite(host: &str,socks5: Option<u32>,xonly_pair: XOnlyPair,  priv_invite_code: &str)->Result<String, S5Error>{
    let full_url = host.to_string() + &APIEndPoint::UserInvite.to_string();
    let nonce = nonce();
    let signature = sign_request(xonly_pair.clone(), HttpMethod::Get, APIEndPoint::UserInvite, &nonce).unwrap();
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
        .set(&HttpHeader::UserInvite.to_string(), priv_invite_code)
        .set(&HttpHeader::Signature.to_string(), &signature)
        .set(&HttpHeader::Pubkey.to_string(), &xonly_pair.pubkey.to_string())
        .set(&HttpHeader::Nonce.to_string(), &nonce)
        .call()
        {
            Ok(response)=>  Ok(
                match AdminInviteResponse::structify(&response.into_string().unwrap()){
                    Ok(result)=>result.invite_code,
                    Err(e) =>{
                        return Err(e);
                    }
                }
            ),
            Err(e)=>{
                return Err(S5Error::from_ureq(e))
            }
        }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct IdentityRegisterRequest{
    username: String
}
impl IdentityRegisterRequest{
    pub fn new(username: &str)->IdentityRegisterRequest{
        IdentityRegisterRequest {
            username: username.to_string()
        }
    }
}

pub fn register(host: &str, socks5: Option<u32>, xonly_pair: XOnlyPair, invite_code: &str, username: &str)->Result<(), S5Error>{
    let full_url = host.to_string() + &APIEndPoint::Identity.to_string();
    let nonce = nonce();
    let signature = sign_request(xonly_pair.clone(), HttpMethod::Post, APIEndPoint::Identity, &nonce).unwrap();
    let body = IdentityRegisterRequest::new(&username.to_lowercase());
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
        .set(&HttpHeader::InviteCode.to_string(), invite_code)
        .set(&HttpHeader::Signature.to_string(), &signature)
        .set(&HttpHeader::Pubkey.to_string(), &xonly_pair.pubkey.to_string())
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
pub struct AllIdentitiesResponse{
    pub identities: Vec<MemberIdentity>
}

impl AllIdentitiesResponse{
    pub fn structify(stringified: &str) -> Result<AllIdentitiesResponse, S5Error> {
        match serde_json::from_str(stringified) {
            Ok(result) => Ok(result),
            Err(_) => {
                Err(S5Error::new(ErrorKind::Internal, "Error stringifying AllIdentitiesResponse"))
            }
        }
    }
}

pub fn get_all(host: &str,socks5: Option<u32>, xonly_pair: XOnlyPair)->Result<Vec<MemberIdentity>, S5Error>{
    let full_url = host.to_string() + &APIEndPoint::AllIdentities.to_string();
    let nonce = nonce();
    let signature = sign_request(xonly_pair.clone(), HttpMethod::Get, APIEndPoint::AllIdentities, &nonce).unwrap();
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
            Ok(response)=>
                match AllIdentitiesResponse::structify(&response.into_string().unwrap())
                {
                    Ok(result)=>Ok(result.identities),
                    Err(e) =>{
                        Err(e)
                    }
                },
            Err(e)=>{
                Err(S5Error::from_ureq(e))
            }
        }
}

pub fn remove(host: &str, socks5: Option<u32>, xonly_pair: XOnlyPair)->Result<(), S5Error>{
    let full_url = host.to_string() + &APIEndPoint::Identity.to_string();
    let nonce = nonce();
    let signature = sign_request(xonly_pair.clone(), HttpMethod::Delete, APIEndPoint::Identity, &nonce).unwrap();
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
        .set(&HttpHeader::Pubkey.to_string(), &xonly_pair.pubkey.to_string())
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::key::ec;
    use crate::key::seed;
    use bitcoin::network::constants::Network;

    #[test]
    #[ignore]
    fn test_identities_dto(){
        let url = "http://localhost:3021";
        // ADMIN INVITE
        let admin_invite_code = "098f6bcd4621d373cade4e832627b4f6";
        let client_invite_code = admin_invite(url,None, admin_invite_code,InvitePermission::Standard).unwrap();
        assert_eq!(client_invite_code.len() , 32);
        // REGISTER USER
        let seed = seed::generate(24, "", Network::Bitcoin).unwrap();
        let keys = XOnlyPair::from_keypair(ec::keypair_from_xprv_str(&seed.xprv.to_string()).unwrap());
        let nonce = nonce();
        let username = "ishi".to_string() + &nonce[0..5].to_lowercase();
        register(url,None,  keys.clone(), &client_invite_code, &username).unwrap();
        // GET ALL USERS
        let identities = get_all(url,None,  keys.clone()).unwrap();
        // println!("{:#?}",identities);
        let user_count = identities.len();
        assert!(user_count>0);
        // REMOVE ONE USER
        remove(url,None,  keys).unwrap();
    }
}