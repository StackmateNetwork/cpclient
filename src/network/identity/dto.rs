use serde::{Deserialize, Serialize};
use ureq::{Proxy, AgentBuilder};
use crate::key::encryption::{nonce};
use crate::key::ec::{XOnlyPair};
use crate::network::handler::{HttpHeader,HttpMethod,APIEndPoint, InvitePermission, ServerStatusResponse, sign_request};
use crate::network::identity::model::{ServerIdentity,Invitation,Members,InvitationDetail};
use crate::util::e::{ErrorKind, S5Error};


pub fn get_server_id(host: String,socks5: Option<u32>, xonly_pair: XOnlyPair)->Result<ServerIdentity, S5Error>{
    let full_url = host + &APIEndPoint::ServerIdentity.to_string();
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
            Ok(response)=>{
                let response = response.into_string().unwrap();
                match ServerIdentity::structify(&response)
                {
                    Ok(result)=>return Ok(result),
                    Err(e) =>{
                        return Err(e)
                    }
                }
            },
            Err(e)=>{
                Err(S5Error::from_ureq(e))
            }
        }
}

pub fn admin_invite(host: String,socks5: Option<u32>, admin_secret: String, permission: InvitePermission)->Result<Invitation, S5Error>{
    let full_url = host + &APIEndPoint::AdminInvite(permission).to_string();
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
        .set(&HttpHeader::AdminInvite.to_string(), &admin_secret)
        .call()
        {
            Ok(response)=>  Ok(
                match Invitation::structify(&response.into_string().unwrap()){
                    Ok(result)=>result,
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

pub fn user_invite(host: String,socks5: Option<u32>,xonly_pair: XOnlyPair,  priv_invite_code: String)->Result<Invitation, S5Error>{
    let full_url = host + &APIEndPoint::UserInvite.to_string();
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
        .set(&HttpHeader::UserInvite.to_string(), &priv_invite_code)
        .set(&HttpHeader::Signature.to_string(), &signature)
        .set(&HttpHeader::Pubkey.to_string(), &xonly_pair.pubkey.to_string())
        .set(&HttpHeader::Nonce.to_string(), &nonce)
        .call()
        {
            Ok(response)=>  Ok(
                match Invitation::structify(&response.into_string().unwrap()){
                    Ok(result)=>result,
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

pub fn register(host: String, socks5: Option<u32>, xonly_pair: XOnlyPair, invite_code: String, username: String)->Result<InvitationDetail, S5Error>{
    let full_url = host + &APIEndPoint::Identity.to_string();
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
        .set(&HttpHeader::InviteCode.to_string(), &invite_code)
        .set(&HttpHeader::Signature.to_string(), &signature)
        .set(&HttpHeader::Pubkey.to_string(), &xonly_pair.pubkey.to_string())
        .set(&HttpHeader::Nonce.to_string(), &nonce)
        .send_json(body){
            Ok(response)=>  Ok(
                match InvitationDetail::structify(&response.into_string().unwrap()){
                    Ok(result)=>result,
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


pub fn get_all(host: String,socks5: Option<u32>, xonly_pair: XOnlyPair)->Result<Members, S5Error>{
    let full_url = host + &APIEndPoint::AllIdentities.to_string();
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
                match Members::structify(&response.into_string().unwrap())
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

pub fn delete(host: String, socks5: Option<u32>, xonly_pair: XOnlyPair)->Result<(), S5Error>{
    let full_url = host + &APIEndPoint::Identity.to_string();
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
                            Err(S5Error::new(ErrorKind::Network, "Server returned a false status. This resource might have already left."))
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
        let url = "http://localhost:3021".to_string();
        // ADMIN INVITE
        let admin_invite_code = "098f6bcd4621d373cade4e832627b4f6".to_string();
        let client_invite_code = admin_invite(url.clone(),None, admin_invite_code,InvitePermission::Standard).unwrap();
        assert_eq!(client_invite_code.invite_code.len() , 32);
        // REGISTER USER
        let seed = seed::MasterKeySeed::generate(24, "", Network::Bitcoin).unwrap();
        let keys = XOnlyPair::from_keypair(ec::keypair_from_xprv_str(&seed.xprv.to_string()).unwrap());
        let nonce = nonce();
        let username = "ishi".to_string() + &nonce[0..5].to_lowercase();
        register(url.clone(),None,  keys.clone(), client_invite_code.invite_code, username).unwrap();
        // GET ALL USERS
        let members = get_all(url.clone(),None,  keys.clone()).unwrap();
        // println!("{:#?}",members);
        let user_count = members.identities.len();
        assert!(user_count>0);
        // leave the network
        delete(url.clone(),None,  keys).unwrap();
    }
}