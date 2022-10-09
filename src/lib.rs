#![allow(dead_code)]
use std::alloc::System;
#[global_allocator]
static A: System = System;
use std::ffi::{CStr, CString};
use std::str::FromStr;
use std::os::raw::c_char;
use bdk::bitcoin::util::bip32::ExtendedPrivKey;

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

/// CREATE SOCIAL ROOT
/// USES BIP85 XPRV APPLICATION TO GENERATE SOCIAL IDENTITY ROOT KEY
/// FURTHER APPLICATION KEYS WILL BE DERIVED FROM THIS ROOT.
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

    match identity::dto::get_server_id(&hostname, socks5, xonly_pair){
        Ok(result)=>result.c_stringify(),
        Err(e)=>e.c_stringify()
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        let result = 2 + 2;
        assert_eq!(result, 4);
    }
}
