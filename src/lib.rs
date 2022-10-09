#![allow(dead_code)]
use std::alloc::System;
#[global_allocator]
static A: System = System;
use std::ffi::{CStr};
// use std::str::FromStr;
use std::os::raw::c_char;
// use bdk::bitcoin::util::bip32::ExtendedPrivKey;

mod key;
use crate::key::{child,ec};

mod network;
use crate::network::identity;
mod util;
use crate::util::e::{ErrorKind,S5Error};

/// CREATE SOCIAL ROOT
/// USES BIP85 XPRV APPLICATION TO GENERATE SOCIAL IDENTITY ROOT KEY
/// FURTHER APPLICATION KEYS WILL BE DERIVED FROM THIS ROOT.
/// # Safety
/// - This function is unsafe because it dereferences and a returns raw pointer.
/// - ENSURE that result is passed into cstring_free(ptr: *mut c_char) after use.
#[no_mangle]
pub unsafe extern "C" fn create_social_root(
    master_root: *const c_char,
    account: *const c_char,
) -> *mut c_char {
    let master_root = CStr::from_ptr(master_root);
    let master_root:String = match master_root.to_str() {
        Ok(string) => string.to_string(),
        Err(_) => return S5Error::new(ErrorKind::Input,"Could not convert master root to String").c_stringify(),
    };

    let account = CStr::from_ptr(account);
    let account:u32 = match account.to_str() {
        Ok(string) => match string.parse::<u32>(){
            Ok(result)=>result,
            Err(_)=>return S5Error::new(ErrorKind::Input,"Could not parse account number to uint32").c_stringify()
        },
        Err(_) => return S5Error::new(ErrorKind::Input,"Could not convert account number to String").c_stringify(),
    };

    match child::social_root(master_root, account){
        Ok(result)=>child::SocialRoot::new(result).c_stringify(),
        Err(e)=>e.c_stringify()
    }
}

/// GET SERVER IDENTITY
/// GETS SERVER NAME & KIND (PRIVATE OR PUBLIC)
/// PRIVATE SERVERS REQUIRE AN INVITE
/// PUBLIC SERVERS REQUIRE A PAYMENT
/// # Safety
/// - This function is unsafe because it dereferences and a returns raw pointer.
/// - ENSURE that result is passed into cstring_free(ptr: *mut c_char) after use.
#[no_mangle]
pub unsafe extern "C" fn server_identity(
    hostname: *const c_char,
    socks5: *const c_char,
    social_root: *const c_char,
) -> *mut c_char {
    let hostname = CStr::from_ptr(hostname);
    let hostname:String = match hostname.to_str() {
        Ok(string) => string.to_string(),
        Err(_) => return S5Error::new(ErrorKind::Input,"Could not convert hostname to String").c_stringify(),
    };

    let socks5 = CStr::from_ptr(socks5);
    let socks5:Option<u32> = match socks5.to_str() {
        Ok(string) => match string.parse::<u32>(){
            Ok(result)=>if result == 0 {
                None
            }else{
                Some(result)
            },
            Err(_)=>return S5Error::new(ErrorKind::Input,"Could not parse socks5 port to uint32").c_stringify()
        },
        Err(_) => return S5Error::new(ErrorKind::Input,"Could not convert socks5 port to String").c_stringify(),
    };
    let social_root = CStr::from_ptr(social_root);
    let social_root:String = match social_root.to_str() {
        Ok(string) => string.to_string(),
        Err(_) => return S5Error::new(ErrorKind::Input,"Could not convert social root to String").c_stringify(),
    };
    let keypair = match ec::keypair_from_xprv_str(&social_root){
        Ok(keypair)=>keypair,
        Err(e)=>return e.c_stringify(),
    };
    let xonly_pair = ec::XOnlyPair::from_keypair(keypair);

    match identity::dto::get_server_id(hostname, socks5, xonly_pair){
        Ok(result)=>result.c_stringify(),
        Err(e)=>e.c_stringify()
    }
}

/// GENERATE AN INVITE CODE AS ADMIN
/// `kind` must be either "standard/std" or "privileged/priv"
/// `count` is how many users a privileged user can invite (use 0 for standard invites)
/// # Safety
/// - This function is unsafe because it dereferences and a returns raw pointer.
/// - ENSURE that result is passed into cstring_free(ptr: *mut c_char) after use.
#[no_mangle]
pub unsafe extern "C" fn admin_invite(
    hostname: *const c_char,
    socks5: *const c_char,
    admin_secret: *const c_char,
    kind: *const c_char,
    count: *const c_char,
) -> *mut c_char {
    let hostname = CStr::from_ptr(hostname);
    let hostname:String = match hostname.to_str() {
        Ok(string) => string.to_string(),
        Err(_) => return S5Error::new(ErrorKind::Input,"Could not convert hostname to String").c_stringify(),
    };

    let socks5 = CStr::from_ptr(socks5);
    let socks5:Option<u32> = match socks5.to_str() {
        Ok(string) => match string.parse::<u32>(){
            Ok(result)=>if result == 0 {
                None
            }else{
                Some(result)
            },
            Err(_)=>return S5Error::new(ErrorKind::Input,"Could not parse socks5 port to uint32").c_stringify()
        },
        Err(_) => return S5Error::new(ErrorKind::Input,"Could not convert socks5 port to String").c_stringify(),
    };
    let admin_secret = CStr::from_ptr(admin_secret);
    let admin_secret:String = match admin_secret.to_str() {
        Ok(string) => string.to_string(),
        Err(_) => return S5Error::new(ErrorKind::Input,"Could not convert admin secret to String").c_stringify(),
    };
   
    let kind = CStr::from_ptr(kind);
    let kind:String = match kind.to_str() {
        Ok(string) => string.to_string().to_lowercase(),
        Err(_) => return S5Error::new(ErrorKind::Input,"Could not convert kind to String").c_stringify(),
    };
   
    let count = CStr::from_ptr(count);
    let count:usize = match count.to_str() {
        Ok(string) => match string.parse::<usize>(){
            Ok(result)=>result,
            Err(_)=>return S5Error::new(ErrorKind::Input,"Could not parse count kind to usize").c_stringify(),
        },
        Err(_) => return S5Error::new(ErrorKind::Input,"Could not count to String").c_stringify(),
    };
    
    let permission = if kind.starts_with("priv"){
        network::handler::InvitePermission::Privilege(count)
    }else{
        network::handler::InvitePermission::Standard
    };

    match identity::dto::admin_invite(hostname, socks5, admin_secret, permission){
        Ok(result)=>result.c_stringify(),
        Err(e)=>e.c_stringify()
    }
}

/// GENERATE AN INVITE CODE AS PRIVILEGED USER
/// CAN ONLY GENERATE STANDARD INVITES
/// # Safety
/// - This function is unsafe because it dereferences and a returns raw pointer.
/// - ENSURE that result is passed into cstring_free(ptr: *mut c_char) after use.
#[no_mangle]
pub unsafe extern "C" fn priv_user_invite(
    hostname: *const c_char,
    socks5: *const c_char,
    social_root: *const c_char,
    invite_code: *const c_char,
) -> *mut c_char {
    let hostname = CStr::from_ptr(hostname);
    let hostname:String = match hostname.to_str() {
        Ok(string) => string.to_string(),
        Err(_) => return S5Error::new(ErrorKind::Input,"Could not convert hostname to String").c_stringify(),
    };

    let socks5 = CStr::from_ptr(socks5);
    let socks5:Option<u32> = match socks5.to_str() {
        Ok(string) => match string.parse::<u32>(){
            Ok(result)=>if result == 0 {
                None
            }else{
                Some(result)
            },
            Err(_)=>return S5Error::new(ErrorKind::Input,"Could not parse socks5 port to uint32").c_stringify()
        },
        Err(_) => return S5Error::new(ErrorKind::Input,"Could not convert socks5 port to String").c_stringify(),
    };

    let invite_code = CStr::from_ptr(invite_code);
    let invite_code:String = match invite_code.to_str() {
        Ok(string) => string.to_string(),
        Err(_) => return S5Error::new(ErrorKind::Input,"Could not convert invite code to String").c_stringify(),
    };
    let social_root = CStr::from_ptr(social_root);
    let social_root:String = match social_root.to_str() {
        Ok(string) => string.to_string(),
        Err(_) => return S5Error::new(ErrorKind::Input,"Could not convert social root to String").c_stringify(),
    };
    let keypair = match ec::keypair_from_xprv_str(&social_root){
        Ok(keypair)=>keypair,
        Err(e)=>return e.c_stringify(),
    };
    let xonly_pair = ec::XOnlyPair::from_keypair(keypair);

    match identity::dto::user_invite(hostname, socks5, xonly_pair, invite_code){
        Ok(result)=>result.c_stringify(),
        Err(e)=>e.c_stringify()
    }
}

/// GET ALL MEMBERS ON THE SERVER
/// USE TO ENSURE USERNAME OF CHOICE IS NOT TAKEN
/// # Safety
/// - This function is unsafe because it dereferences and a returns raw pointer.
/// - ENSURE that result is passed into cstring_free(ptr: *mut c_char) after use.
#[no_mangle]
pub unsafe extern "C" fn get_members(
    hostname: *const c_char,
    socks5: *const c_char,
    social_root: *const c_char,
) -> *mut c_char {
    let hostname = CStr::from_ptr(hostname);
    let hostname:String = match hostname.to_str() {
        Ok(string) => string.to_string(),
        Err(_) => return S5Error::new(ErrorKind::Input,"Could not convert hostname to String").c_stringify(),
    };

    let socks5 = CStr::from_ptr(socks5);
    let socks5:Option<u32> = match socks5.to_str() {
        Ok(string) => match string.parse::<u32>(){
            Ok(result)=>if result == 0 {
                None
            }else{
                Some(result)
            },
            Err(_)=>return S5Error::new(ErrorKind::Input,"Could not parse socks5 port to uint32").c_stringify()
        },
        Err(_) => return S5Error::new(ErrorKind::Input,"Could not convert socks5 port to String").c_stringify(),
    };
    let social_root = CStr::from_ptr(social_root);
    let social_root:String = match social_root.to_str() {
        Ok(string) => string.to_string(),
        Err(_) => return S5Error::new(ErrorKind::Input,"Could not convert social root to String").c_stringify(),
    };
    let keypair = match ec::keypair_from_xprv_str(&social_root){
        Ok(keypair)=>keypair,
        Err(e)=>return e.c_stringify(),
    };
    let xonly_pair = ec::XOnlyPair::from_keypair(keypair);

    match identity::dto::get_all(hostname, socks5, xonly_pair){
        Ok(result)=>result.c_stringify(),
        Err(e)=>e.c_stringify()
    }
}

/// REGISTER TO A PRIVATE SERVER
/// # Safety
/// - This function is unsafe because it dereferences and a returns raw pointer.
/// - ENSURE that result is passed into cstring_free(ptr: *mut c_char) after use.
#[no_mangle]
pub unsafe extern "C" fn join(
    hostname: *const c_char,
    socks5: *const c_char,
    social_root: *const c_char,
    username: *const c_char,
    invite_code: *const c_char,
) -> *mut c_char {
    let hostname = CStr::from_ptr(hostname);
    let hostname:String = match hostname.to_str() {
        Ok(string) => string.to_string(),
        Err(_) => return S5Error::new(ErrorKind::Input,"Could not convert hostname to String").c_stringify(),
    };

    let socks5 = CStr::from_ptr(socks5);
    let socks5:Option<u32> = match socks5.to_str() {
        Ok(string) => match string.parse::<u32>(){
            Ok(result)=>if result == 0 {
                None
            }else{
                Some(result)
            },
            Err(_)=>return S5Error::new(ErrorKind::Input,"Could not parse socks5 port to uint32").c_stringify()
        },
        Err(_) => return S5Error::new(ErrorKind::Input,"Could not convert socks5 port to String").c_stringify(),
    };
    let social_root = CStr::from_ptr(social_root);
    let social_root:String = match social_root.to_str() {
        Ok(string) => string.to_string(),
        Err(_) => return S5Error::new(ErrorKind::Input,"Could not convert social root to String").c_stringify(),
    };
    let keypair = match ec::keypair_from_xprv_str(&social_root){
        Ok(keypair)=>keypair,
        Err(e)=>return e.c_stringify(),
    };
    let xonly_pair = ec::XOnlyPair::from_keypair(keypair);

    let username = CStr::from_ptr(username);
    let username:String = match username.to_str() {
        Ok(string) => string.to_string(),
        Err(_) => return S5Error::new(ErrorKind::Input,"Could not convert username to String").c_stringify(),
    };

    let invite_code = CStr::from_ptr(invite_code);
    let invite_code:String = match invite_code.to_str() {
        Ok(string) => string.to_string(),
        Err(_) => return S5Error::new(ErrorKind::Input,"Could not convert invite_code to String").c_stringify(),
    };

    match identity::dto::register(hostname, socks5, xonly_pair,invite_code,username){
        Ok(_)=>network::handler::ServerStatusResponse::new(true).c_stringify(),
        Err(e)=>e.c_stringify()
    }
}

/// REGISTER TO A PRIVATE SERVER
/// # Safety
/// - This function is unsafe because it dereferences and a returns raw pointer.
/// - ENSURE that result is passed into cstring_free(ptr: *mut c_char) after use.
#[no_mangle]
pub unsafe extern "C" fn leave(
    hostname: *const c_char,
    socks5: *const c_char,
    social_root: *const c_char,
) -> *mut c_char {
    let hostname = CStr::from_ptr(hostname);
    let hostname:String = match hostname.to_str() {
        Ok(string) => string.to_string(),
        Err(_) => return S5Error::new(ErrorKind::Input,"Could not convert hostname to String").c_stringify(),
    };

    let socks5 = CStr::from_ptr(socks5);
    let socks5:Option<u32> = match socks5.to_str() {
        Ok(string) => match string.parse::<u32>(){
            Ok(result)=>if result == 0 {
                None
            }else{
                Some(result)
            },
            Err(_)=>return S5Error::new(ErrorKind::Input,"Could not parse socks5 port to uint32").c_stringify()
        },
        Err(_) => return S5Error::new(ErrorKind::Input,"Could not convert socks5 port to String").c_stringify(),
    };
    let social_root = CStr::from_ptr(social_root);
    let social_root:String = match social_root.to_str() {
        Ok(string) => string.to_string(),
        Err(_) => return S5Error::new(ErrorKind::Input,"Could not convert social root to String").c_stringify(),
    };
    let keypair = match ec::keypair_from_xprv_str(&social_root){
        Ok(keypair)=>keypair,
        Err(e)=>return e.c_stringify(),
    };
    let xonly_pair = ec::XOnlyPair::from_keypair(keypair);

    match identity::dto::delete(hostname, socks5, xonly_pair){
        Ok(_)=>network::handler::ServerStatusResponse::new(true).c_stringify(),
        Err(e)=>e.c_stringify()
    }
}



#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::{CStr, CString};

    #[test]
    // #[ignore]
    fn test_ffi_composite() {
        unsafe {
            //
            //
            // CREATE SOCIAL ROOT
            //
            //
            let master_xprv = "xprv9s21ZrQH143K3ncAtUgVY1zDx6aUQN5K2Jn5zQSFT27jCCNLz6APws3GcNsZXwvP64XaveqPkrG4kQGuWbRTo8CMUwZFkzRA95LF8o88qeb";
            let master_xprv_cstr = CString::new(master_xprv).unwrap().into_raw();
            let account = "0";
            let account_cstr = CString::new(account).unwrap().into_raw();
            let expected_child = "xprv9s21ZrQH143K3KdqdcqNykVWEQQhPcpThaaZ4yMhUSneiaxr5kMMXt4E6msuSv8znKK7gxo52soSmV2rp9xBRKTn4NXDwLH2w5Li1DDU7es";
            let result_ptr = create_social_root(
                master_xprv_cstr, 
                account_cstr
            );
            let result_cstr = CStr::from_ptr(result_ptr);
            let result_str = result_cstr.to_str().unwrap();
            let child = key::child::SocialRoot::structify(result_str).unwrap();
            assert_eq!(child.social_root, expected_child);
            //
            //
            // GET SERVER IDENTITY
            //
            //
            let hostname = "http://localhost:3021".to_string();
            let hostname_cstr = CString::new(hostname.clone()).unwrap().into_raw();
            let socks5 = "0";
            let socks5_cstr = CString::new(socks5).unwrap().into_raw();
            let social_root_cstr =  CString::new(child.social_root).unwrap().into_raw();
            let result_ptr = server_identity(
                hostname_cstr,
                socks5_cstr,
                social_root_cstr,
            );
            let result_cstr = CStr::from_ptr(result_ptr);
            let result_str = result_cstr.to_str().unwrap();
            let server_id = identity::model::ServerIdentity::structify(result_str).unwrap();
            assert_eq!(server_id.kind, "PRIVATE".to_string());
            //
            //
            // GET MEMBERS
            //
            //
            let result_ptr = get_members(
                hostname_cstr,
                socks5_cstr,
                social_root_cstr,
            );
            let result_cstr = CStr::from_ptr(result_ptr);
            let result_str = result_cstr.to_str().unwrap();
            let members = identity::model::Members::structify(result_str);
            assert!(members.is_ok());
            //
            //
            // ADMIN OPS (GET INVITE)
            //
            //
            let admin_secret = "098f6bcd4621d373cade4e832627b4f6";
            let admin_secret_cstr = CString::new(admin_secret).unwrap().into_raw();
            let kind = "priv";
            let kind_cstr = CString::new(kind).unwrap().into_raw();
            let count = "1";
            let count_cstr = CString::new(count).unwrap().into_raw();
            let result_ptr = admin_invite(
                hostname_cstr,
                socks5_cstr,
                admin_secret_cstr,
                kind_cstr,
                count_cstr,
            );
            let result_cstr = CStr::from_ptr(result_ptr);
            let result_str = result_cstr.to_str().unwrap();
            let invitation = identity::model::Invitation::structify(result_str).unwrap();
            assert_eq!(invitation.invite_code.len() , 32);
            //
            //
            // REGISTER
            //
            //
            let nonce = key::encryption::nonce();
            let username = "ishi".to_string() + &nonce[0..5].to_lowercase();
            let username_cstr = CString::new(username.clone()).unwrap().into_raw();
            let invite_code_cstr = CString::new(invitation.invite_code.clone()).unwrap().into_raw();
            let result_ptr = join(
                hostname_cstr,
                socks5_cstr,
                social_root_cstr,
                username_cstr,
                invite_code_cstr
            );
            let result_cstr = CStr::from_ptr(result_ptr);
            let result_str = result_cstr.to_str().unwrap();
            let response = network::handler::ServerStatusResponse::structify(result_str).unwrap();
            assert!(response.status);
            //
            //
            // LEAVE
            //
            //
            let result_ptr = leave(
                hostname_cstr,
                socks5_cstr,
                social_root_cstr,
            );
            let result_cstr = CStr::from_ptr(result_ptr);
            let result_str = result_cstr.to_str().unwrap();
            let response = network::handler::ServerStatusResponse::structify(result_str).unwrap();
            assert!(response.status);

        }
    }

}
