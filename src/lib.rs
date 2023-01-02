#![allow(dead_code)]
use std::alloc::System;
#[global_allocator]
static A: System = System;
use std::ffi::CStr;
use std::os::raw::c_char;
use std::str::FromStr;
// use bdk::bitcoin::util::bip32::ExtendedPrivKey;
use bitcoin::secp256k1::XOnlyPublicKey;
use bitcoin::util::bip32::ExtendedPrivKey;

mod key;
use crate::key::{child, ec};

mod network;
use crate::network::{identity, post};
mod util;
use crate::util::e::{ErrorKind, S5Error};

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
    let master_root: String = match master_root.to_str() {
        Ok(string) => string.to_string(),
        Err(_) => {
            return S5Error::new(ErrorKind::Input, "Could not convert master root to String")
                .c_stringify()
        }
    };

    let account = CStr::from_ptr(account);
    let account: u32 = match account.to_str() {
        Ok(string) => match string.parse::<u32>() {
            Ok(result) => result,
            Err(_) => {
                return S5Error::new(ErrorKind::Input, "Could not parse account number to uint32")
                    .c_stringify()
            }
        },
        Err(_) => {
            return S5Error::new(
                ErrorKind::Input,
                "Could not convert account number to String",
            )
            .c_stringify()
        }
    };

    match child::social_root(master_root, account) {
        Ok(result) => result.c_stringify(),
        Err(e) => e.c_stringify(),
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
    let hostname: String = match hostname.to_str() {
        Ok(string) => string.to_string(),
        Err(_) => {
            return S5Error::new(ErrorKind::Input, "Could not convert hostname to String")
                .c_stringify()
        }
    };

    let socks5 = CStr::from_ptr(socks5);
    let socks5: Option<u32> = match socks5.to_str() {
        Ok(string) => match string.parse::<u32>() {
            Ok(result) => {
                if result == 0 {
                    None
                } else {
                    Some(result)
                }
            }
            Err(_) => {
                return S5Error::new(ErrorKind::Input, "Could not parse socks5 port to uint32")
                    .c_stringify()
            }
        },
        Err(_) => {
            return S5Error::new(ErrorKind::Input, "Could not convert socks5 port to String")
                .c_stringify()
        }
    };
    let social_root = CStr::from_ptr(social_root);
    let social_root: String = match social_root.to_str() {
        Ok(string) => string.to_string(),
        Err(_) => {
            return S5Error::new(ErrorKind::Input, "Could not convert social root to String")
                .c_stringify()
        }
    };
    let keypair = match ec::keypair_from_xprv_str(&social_root) {
        Ok(keypair) => keypair,
        Err(e) => return e.c_stringify(),
    };
    let xonly_pair = ec::XOnlyPair::from_keypair(keypair);

    match identity::dto::get_server_id(hostname, socks5, xonly_pair) {
        Ok(result) => result.c_stringify(),
        Err(e) => e.c_stringify(),
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
    let hostname: String = match hostname.to_str() {
        Ok(string) => string.to_string(),
        Err(_) => {
            return S5Error::new(ErrorKind::Input, "Could not convert hostname to String")
                .c_stringify()
        }
    };

    let socks5 = CStr::from_ptr(socks5);
    let socks5: Option<u32> = match socks5.to_str() {
        Ok(string) => match string.parse::<u32>() {
            Ok(result) => {
                if result == 0 {
                    None
                } else {
                    Some(result)
                }
            }
            Err(_) => {
                return S5Error::new(ErrorKind::Input, "Could not parse socks5 port to uint32")
                    .c_stringify()
            }
        },
        Err(_) => {
            return S5Error::new(ErrorKind::Input, "Could not convert socks5 port to String")
                .c_stringify()
        }
    };
    let admin_secret = CStr::from_ptr(admin_secret);
    let admin_secret: String = match admin_secret.to_str() {
        Ok(string) => string.to_string(),
        Err(_) => {
            return S5Error::new(ErrorKind::Input, "Could not convert admin secret to String")
                .c_stringify()
        }
    };

    let kind = CStr::from_ptr(kind);
    let kind: String = match kind.to_str() {
        Ok(string) => string.to_string().to_lowercase(),
        Err(_) => {
            return S5Error::new(ErrorKind::Input, "Could not convert kind to String").c_stringify()
        }
    };

    let count = CStr::from_ptr(count);
    let count: usize = match count.to_str() {
        Ok(string) => match string.parse::<usize>() {
            Ok(result) => result,
            Err(_) => {
                return S5Error::new(ErrorKind::Input, "Could not parse count kind to usize")
                    .c_stringify()
            }
        },
        Err(_) => return S5Error::new(ErrorKind::Input, "Could not count to String").c_stringify(),
    };

    let permission = if kind.starts_with("priv") {
        network::handler::InvitePermission::Privilege(count)
    } else {
        network::handler::InvitePermission::Standard
    };

    match identity::dto::admin_invite(hostname, socks5, admin_secret, permission) {
        Ok(result) => result.c_stringify(),
        Err(e) => e.c_stringify(),
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
    let hostname: String = match hostname.to_str() {
        Ok(string) => string.to_string(),
        Err(_) => {
            return S5Error::new(ErrorKind::Input, "Could not convert hostname to String")
                .c_stringify()
        }
    };

    let socks5 = CStr::from_ptr(socks5);
    let socks5: Option<u32> = match socks5.to_str() {
        Ok(string) => match string.parse::<u32>() {
            Ok(result) => {
                if result == 0 {
                    None
                } else {
                    Some(result)
                }
            }
            Err(_) => {
                return S5Error::new(ErrorKind::Input, "Could not parse socks5 port to uint32")
                    .c_stringify()
            }
        },
        Err(_) => {
            return S5Error::new(ErrorKind::Input, "Could not convert socks5 port to String")
                .c_stringify()
        }
    };

    let invite_code = CStr::from_ptr(invite_code);
    let invite_code: String = match invite_code.to_str() {
        Ok(string) => string.to_string(),
        Err(_) => {
            return S5Error::new(ErrorKind::Input, "Could not convert invite code to String")
                .c_stringify()
        }
    };
    let social_root = CStr::from_ptr(social_root);
    let social_root: String = match social_root.to_str() {
        Ok(string) => string.to_string(),
        Err(_) => {
            return S5Error::new(ErrorKind::Input, "Could not convert social root to String")
                .c_stringify()
        }
    };
    let keypair = match ec::keypair_from_xprv_str(&social_root) {
        Ok(keypair) => keypair,
        Err(e) => return e.c_stringify(),
    };
    let xonly_pair = ec::XOnlyPair::from_keypair(keypair);

    match identity::dto::user_invite(hostname, socks5, xonly_pair, invite_code) {
        Ok(result) => result.c_stringify(),
        Err(e) => e.c_stringify(),
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
    let hostname: String = match hostname.to_str() {
        Ok(string) => string.to_string(),
        Err(_) => {
            return S5Error::new(ErrorKind::Input, "Could not convert hostname to String")
                .c_stringify()
        }
    };

    let socks5 = CStr::from_ptr(socks5);
    let socks5: Option<u32> = match socks5.to_str() {
        Ok(string) => match string.parse::<u32>() {
            Ok(result) => {
                if result == 0 {
                    None
                } else {
                    Some(result)
                }
            }
            Err(_) => {
                return S5Error::new(ErrorKind::Input, "Could not parse socks5 port to uint32")
                    .c_stringify()
            }
        },
        Err(_) => {
            return S5Error::new(ErrorKind::Input, "Could not convert socks5 port to String")
                .c_stringify()
        }
    };
    let social_root = CStr::from_ptr(social_root);
    let social_root: String = match social_root.to_str() {
        Ok(string) => string.to_string(),
        Err(_) => {
            return S5Error::new(ErrorKind::Input, "Could not convert social root to String")
                .c_stringify()
        }
    };
    let keypair = match ec::keypair_from_xprv_str(&social_root) {
        Ok(keypair) => keypair,
        Err(e) => return e.c_stringify(),
    };
    let xonly_pair = ec::XOnlyPair::from_keypair(keypair);

    match identity::dto::get_all(hostname, socks5, xonly_pair) {
        Ok(result) => result.c_stringify(),
        Err(e) => e.c_stringify(),
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
    let hostname: String = match hostname.to_str() {
        Ok(string) => string.to_string(),
        Err(_) => {
            return S5Error::new(ErrorKind::Input, "Could not convert hostname to String")
                .c_stringify()
        }
    };

    let socks5 = CStr::from_ptr(socks5);
    let socks5: Option<u32> = match socks5.to_str() {
        Ok(string) => match string.parse::<u32>() {
            Ok(result) => {
                if result == 0 {
                    None
                } else {
                    Some(result)
                }
            }
            Err(_) => {
                return S5Error::new(ErrorKind::Input, "Could not parse socks5 port to uint32")
                    .c_stringify()
            }
        },
        Err(_) => {
            return S5Error::new(ErrorKind::Input, "Could not convert socks5 port to String")
                .c_stringify()
        }
    };
    let social_root = CStr::from_ptr(social_root);
    let social_root: String = match social_root.to_str() {
        Ok(string) => string.to_string(),
        Err(_) => {
            return S5Error::new(ErrorKind::Input, "Could not convert social root to String")
                .c_stringify()
        }
    };
    let keypair = match ec::keypair_from_xprv_str(&social_root) {
        Ok(keypair) => keypair,
        Err(e) => return e.c_stringify(),
    };
    let xonly_pair = ec::XOnlyPair::from_keypair(keypair);

    let username = CStr::from_ptr(username);
    let username: String = match username.to_str() {
        Ok(string) => string.to_string(),
        Err(_) => {
            return S5Error::new(ErrorKind::Input, "Could not convert username to String")
                .c_stringify()
        }
    };

    let invite_code = CStr::from_ptr(invite_code);
    let invite_code: String = match invite_code.to_str() {
        Ok(string) => string.to_string(),
        Err(_) => {
            return S5Error::new(ErrorKind::Input, "Could not convert invite_code to String")
                .c_stringify()
        }
    };

    match identity::dto::register(hostname, socks5, xonly_pair, invite_code, username) {
        Ok(result) => result.c_stringify(),
        Err(e) => e.c_stringify(),
    }
}
/// LEAVE A SERVER
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
    let hostname: String = match hostname.to_str() {
        Ok(string) => string.to_string(),
        Err(_) => {
            return S5Error::new(ErrorKind::Input, "Could not convert hostname to String")
                .c_stringify()
        }
    };

    let socks5 = CStr::from_ptr(socks5);
    let socks5: Option<u32> = match socks5.to_str() {
        Ok(string) => match string.parse::<u32>() {
            Ok(result) => {
                if result == 0 {
                    None
                } else {
                    Some(result)
                }
            }
            Err(_) => {
                return S5Error::new(ErrorKind::Input, "Could not parse socks5 port to uint32")
                    .c_stringify()
            }
        },
        Err(_) => {
            return S5Error::new(ErrorKind::Input, "Could not convert socks5 port to String")
                .c_stringify()
        }
    };
    let social_root = CStr::from_ptr(social_root);
    let social_root: String = match social_root.to_str() {
        Ok(string) => string.to_string(),
        Err(_) => {
            return S5Error::new(ErrorKind::Input, "Could not convert social root to String")
                .c_stringify()
        }
    };
    let keypair = match ec::keypair_from_xprv_str(&social_root) {
        Ok(keypair) => keypair,
        Err(e) => return e.c_stringify(),
    };
    let xonly_pair = ec::XOnlyPair::from_keypair(keypair);

    match identity::dto::delete(hostname, socks5, xonly_pair) {
        Ok(_) => network::handler::ServerStatusResponse::new(true).c_stringify(),
        Err(e) => e.c_stringify(),
    }
}
/// CREATE A POST & KEYS
/// `to` must be colon separated `kind:value` of recipient
/// `kind` is the kind of payload (message or secret)
/// `value` is the value of the payload (watch out for special chars and escape chars)
/// # Safety
/// - This function is unsafe because it dereferences and a returns raw pointer.
/// - ENSURE that result is passed into cstring_free(ptr: *mut c_char) after use.
#[no_mangle]
pub unsafe extern "C" fn send_post(
    hostname: *const c_char,
    socks5: *const c_char,
    social_root: *const c_char,
    index: *const c_char,
    to: *const c_char,
    kind: *const c_char,
    value: *const c_char,
) -> *mut c_char {
    let hostname_cstr = CStr::from_ptr(hostname);
    let hostname: String = match hostname_cstr.to_str() {
        Ok(string) => string.to_string(),
        Err(_) => {
            return S5Error::new(ErrorKind::Input, "Could not convert hostname to String")
                .c_stringify()
        }
    };

    let socks5 = CStr::from_ptr(socks5);
    let socks5: Option<u32> = match socks5.to_str() {
        Ok(string) => match string.parse::<u32>() {
            Ok(result) => {
                if result == 0 {
                    None
                } else {
                    Some(result)
                }
            }
            Err(_) => {
                return S5Error::new(ErrorKind::Input, "Could not parse socks5 port to uint32")
                    .c_stringify()
            }
        },
        Err(_) => {
            return S5Error::new(ErrorKind::Input, "Could not convert socks5 port to String")
                .c_stringify()
        }
    };
    let social_root = CStr::from_ptr(social_root);
    let social_root: String = match social_root.to_str() {
        Ok(string) => string.to_string(),
        Err(_) => {
            return S5Error::new(ErrorKind::Input, "Could not convert social root to String")
                .c_stringify()
        }
    };
    let keypair = match ec::keypair_from_xprv_str(&social_root) {
        Ok(keypair) => keypair,
        Err(e) => return e.c_stringify(),
    };
    let xonly_pair = ec::XOnlyPair::from_keypair(keypair);

    let index = CStr::from_ptr(index);
    let index: u32 = match index.to_str() {
        Ok(string) => match string.parse::<u32>() {
            Ok(result) => result,
            Err(_) => {
                return S5Error::new(ErrorKind::Input, "Could not parse index to u32").c_stringify()
            }
        },
        Err(_) => {
            return S5Error::new(ErrorKind::Input, "Could not convert index to String")
                .c_stringify()
        }
    };
    let to = CStr::from_ptr(to);
    let to: post::model::Recipient = match to.to_str() {
        Ok(result) => match post::model::Recipient::from_str(result) {
            Ok(recipient) => recipient,
            Err(e) => return e.c_stringify(),
        },
        Err(_) => {
            return S5Error::new(ErrorKind::Input, "Could not convert to into String").c_stringify()
        }
    };
    let kind = match CStr::from_ptr(kind).to_str() {
        Ok(result) => result,
        Err(_) => {
            return S5Error::new(
                ErrorKind::Input,
                "Could not convert payload kind into String",
            )
            .c_stringify()
        }
    };

    let value = match CStr::from_ptr(value).to_str() {
        Ok(result) => result,
        Err(_) => {
            return S5Error::new(
                ErrorKind::Input,
                "Could not convert payload value into String",
            )
            .c_stringify()
        }
    };

    let payload = format!("{}:{}", kind, value);
    let payload: post::model::Payload = match post::model::Payload::from_str(&payload) {
        Ok(payload) => payload,
        Err(e) => return e.c_stringify(),
    };

    let my_identity = match identity::model::UserIdentity::new(social_root) {
        Ok(result) => result,
        Err(e) => return e.c_stringify(),
    };

    let post = post::model::Post::new(to, payload, xonly_pair.clone());
    let encryption_key = my_identity.derive_encryption_key(index);
    let cypher = post.to_cypher(encryption_key.clone());

    let request = post::dto::ServerPostRequest::new(0, index, &cypher);
    match post::dto::create(hostname.clone(), socks5, xonly_pair.clone(), request) {
        Ok(id) => post::model::PostId::new(id).c_stringify(),
        Err(e) => e.c_stringify(),
    }
}
/// SEND KEYS FOR A POST's RECIPIENTS
/// `recipients` must be a comma separated list of recipients
/// # Safety
/// - This function is unsafe because it dereferences and a returns raw pointer.
/// - ENSURE that result is passed into cstring_free(ptr: *mut c_char) after use.
#[no_mangle]
pub unsafe extern "C" fn send_keys(
    hostname: *const c_char,
    socks5: *const c_char,
    social_root: *const c_char,
    index: *const c_char,
    post_id: *const c_char,
    recipients: *const c_char,
) -> *mut c_char {
    let hostname_cstr = CStr::from_ptr(hostname);
    let hostname: String = match hostname_cstr.to_str() {
        Ok(string) => string.to_string(),
        Err(_) => {
            return S5Error::new(ErrorKind::Input, "Could not convert hostname to String")
                .c_stringify()
        }
    };

    let socks5 = CStr::from_ptr(socks5);
    let socks5: Option<u32> = match socks5.to_str() {
        Ok(string) => match string.parse::<u32>() {
            Ok(result) => {
                if result == 0 {
                    None
                } else {
                    Some(result)
                }
            }
            Err(_) => {
                return S5Error::new(ErrorKind::Input, "Could not parse socks5 port to uint32")
                    .c_stringify()
            }
        },
        Err(_) => {
            return S5Error::new(ErrorKind::Input, "Could not convert socks5 port to String")
                .c_stringify()
        }
    };
    let social_root = CStr::from_ptr(social_root);
    let social_root: String = match social_root.to_str() {
        Ok(string) => string.to_string(),
        Err(_) => {
            return S5Error::new(ErrorKind::Input, "Could not convert social root to String")
                .c_stringify()
        }
    };
    let keypair = match ec::keypair_from_xprv_str(&social_root) {
        Ok(keypair) => keypair,
        Err(e) => return e.c_stringify(),
    };
    let xonly_pair = ec::XOnlyPair::from_keypair(keypair);

    let index = CStr::from_ptr(index);
    let index: u32 = match index.to_str() {
        Ok(string) => match string.parse::<u32>() {
            Ok(result) => result,
            Err(_) => {
                return S5Error::new(ErrorKind::Input, "Could not parse index to u32").c_stringify()
            }
        },
        Err(_) => {
            return S5Error::new(ErrorKind::Input, "Could not convert index to String")
                .c_stringify()
        }
    };

    let post_id = CStr::from_ptr(post_id);
    let post_id: String = match post_id.to_str() {
        Ok(string) => string.to_string(),
        Err(_) => {
            return S5Error::new(ErrorKind::Input, "Could not convert post_id to String")
                .c_stringify()
        }
    };

    let recipients = CStr::from_ptr(recipients);
    let recipients: Vec<XOnlyPublicKey> = match recipients.to_str() {
        Ok(result) => {
            let string_pubkeys: Vec<&str> = result.split(",").collect();
            if string_pubkeys.len() == 0 {
                return S5Error::new(ErrorKind::Input, "Unable to parse recipients.").c_stringify();
            } else {
                let mut xonly_vec: Vec<XOnlyPublicKey> = [].to_vec();
                for pubkey in string_pubkeys.into_iter() {
                    match ec::pubkey_from_str(pubkey) {
                        Ok(result) => xonly_vec.push(result),
                        Err(_) => {
                            return S5Error::new(
                                ErrorKind::Input,
                                "One recipient pubkey is not a valid XOnlyPubKey",
                            )
                            .c_stringify()
                        }
                    };
                }
                xonly_vec
            }
        }
        Err(_) => {
            return S5Error::new(ErrorKind::Input, "Could not convert recipients into String")
                .c_stringify()
        }
    };

    let my_identity = match identity::model::UserIdentity::new(social_root) {
        Ok(result) => result,
        Err(e) => return e.c_stringify(),
    };
    let encryption_key = my_identity.derive_encryption_key(index);
    let decryption_keys = match post::model::DecryptionKey::make_for_many(
        xonly_pair.clone(),
        recipients.clone(),
        encryption_key.clone(),
    ) {
        Ok(keys) => keys,
        Err(e) => return e.c_stringify(),
    };

    match post::dto::keys(
        hostname.clone(),
        socks5,
        xonly_pair.clone(),
        post_id.clone(),
        decryption_keys,
    ) {
        Ok(()) => network::handler::ServerStatusResponse::new(true).c_stringify(),
        Err(e) => return e.c_stringify(),
    }
}
/// GET A SINGLE POST BY ID
/// # Safety
/// - This function is unsafe because it dereferences and a returns raw pointer.
/// - ENSURE that result is passed into cstring_free(ptr: *mut c_char) after use.
#[no_mangle]
pub unsafe extern "C" fn get_one_post(
    hostname: *const c_char,
    socks5: *const c_char,
    social_root: *const c_char,
    post_id: *const c_char,
) -> *mut c_char {
    let hostname_cstr = CStr::from_ptr(hostname);
    let hostname: String = match hostname_cstr.to_str() {
        Ok(string) => string.to_string(),
        Err(_) => {
            return S5Error::new(ErrorKind::Input, "Could not convert hostname to String")
                .c_stringify()
        }
    };

    let socks5 = CStr::from_ptr(socks5);
    let socks5: Option<u32> = match socks5.to_str() {
        Ok(string) => match string.parse::<u32>() {
            Ok(result) => {
                if result == 0 {
                    None
                } else {
                    Some(result)
                }
            }
            Err(_) => {
                return S5Error::new(ErrorKind::Input, "Could not parse socks5 port to uint32")
                    .c_stringify()
            }
        },
        Err(_) => {
            return S5Error::new(ErrorKind::Input, "Could not convert socks5 port to String")
                .c_stringify()
        }
    };
    let social_root = CStr::from_ptr(social_root);
    let social_root: String = match social_root.to_str() {
        Ok(string) => string.to_string(),
        Err(_) => {
            return S5Error::new(ErrorKind::Input, "Could not convert social root to String")
                .c_stringify()
        }
    };
    let keypair = match ec::keypair_from_xprv_str(&social_root) {
        Ok(keypair) => keypair,
        Err(e) => return e.c_stringify(),
    };
    let xonly_pair = ec::XOnlyPair::from_keypair(keypair);
    let social_xprv = match ExtendedPrivKey::from_str(&social_root) {
        Ok(result) => result,
        Err(_) => return S5Error::new(ErrorKind::Key, "BAD XPRV STRING").c_stringify(),
    };

    let post_id = CStr::from_ptr(post_id);
    let post_id: String = match post_id.to_str() {
        Ok(string) => string.to_string(),
        Err(_) => {
            return S5Error::new(ErrorKind::Input, "Could not convert post_id to String")
                .c_stringify()
        }
    };

    let cypherpost = match post::dto::single_post(
        hostname.clone(),
        socks5,
        xonly_pair.clone(),
        post_id.clone(),
    ) {
        Ok(post) => post,
        Err(e) => return e.c_stringify(),
    };

    match cypherpost.decypher(social_xprv) {
        Ok(post) => post.c_stringify(),
        Err(e) => return e.c_stringify(),
    }
}
/// GET ALL POSTS FOR A USER
/// # Safety
/// - This function is unsafe because it dereferences and a returns raw pointer.
/// - ENSURE that result is passed into cstring_free(ptr: *mut c_char) after use.
#[no_mangle]
pub unsafe extern "C" fn get_all_posts(
    hostname: *const c_char,
    socks5: *const c_char,
    social_root: *const c_char,
    genesis_filter: *const c_char,
) -> *mut c_char {
    let hostname_cstr = CStr::from_ptr(hostname);
    let hostname: String = match hostname_cstr.to_str() {
        Ok(string) => string.to_string(),
        Err(_) => {
            return S5Error::new(ErrorKind::Input, "Could not convert hostname to String")
                .c_stringify()
        }
    };

    let socks5 = CStr::from_ptr(socks5);
    let socks5: Option<u32> = match socks5.to_str() {
        Ok(string) => match string.parse::<u32>() {
            Ok(result) => {
                if result == 0 {
                    None
                } else {
                    Some(result)
                }
            }
            Err(_) => {
                return S5Error::new(ErrorKind::Input, "Could not parse socks5 port to uint32")
                    .c_stringify()
            }
        },
        Err(_) => {
            return S5Error::new(ErrorKind::Input, "Could not convert socks5 port to String")
                .c_stringify()
        }
    };
    let social_root = CStr::from_ptr(social_root);
    let social_root: String = match social_root.to_str() {
        Ok(string) => string.to_string(),
        Err(_) => {
            return S5Error::new(ErrorKind::Input, "Could not convert social root to String")
                .c_stringify()
        }
    };
    let social_xprv = match ExtendedPrivKey::from_str(&social_root) {
        Ok(result) => result,
        Err(_) => return S5Error::new(ErrorKind::Key, "BAD XPRV STRING").c_stringify(),
    };
    let xonly_pair = ec::XOnlyPair::from_xprv(social_xprv.clone());

    let genesis_filter = CStr::from_ptr(genesis_filter);
    let genesis_filter: Option<u64> = match genesis_filter.to_str() {
        Ok(string) => match string.parse::<u64>() {
            Ok(value) => {
                if value == 0 {
                    None
                } else {
                    Some(value)
                }
            }
            Err(_) => {
                return S5Error::new(ErrorKind::Key, "Could not parse genesis filter to u64")
                    .c_stringify()
            }
        },
        Err(_) => {
            return S5Error::new(
                ErrorKind::Input,
                "Could not convert genesis filter to String",
            )
            .c_stringify()
        }
    };

    match post::dto::get_all_posts(
        hostname.clone(),
        socks5,
        social_xprv.clone(),
        genesis_filter,
    ) {
        Ok(mut all) => all.to_all_posts_as_chat(xonly_pair.pubkey).c_stringify(),
        Err(e) => e.c_stringify(),
    }
}
/// GET LAST DERIVATION INDEX
/// USERS SHOULD STORE AND UPDATE LAST USED INDEX FOR FORWARD SECRECY
/// USE THIS FUNCTION ONLY IN CASE OF RECOVERY AND LOSS OF LOCAL DATA
/// AVOID USING THIS BEFORE EVERY POST BY KEEPING TRACK OF INDEX LOCALLY
/// # Safety
/// - This function is unsafe because it dereferences and a returns raw pointer.
/// - ENSURE that result is passed into cstring_free(ptr: *mut c_char) after use.
#[no_mangle]
pub unsafe extern "C" fn last_index(
    hostname: *const c_char,
    socks5: *const c_char,
    social_root: *const c_char,
) -> *mut c_char {
    let hostname_cstr = CStr::from_ptr(hostname);
    let hostname: String = match hostname_cstr.to_str() {
        Ok(string) => string.to_string(),
        Err(_) => {
            return S5Error::new(ErrorKind::Input, "Could not convert hostname to String")
                .c_stringify()
        }
    };

    let socks5 = CStr::from_ptr(socks5);
    let socks5: Option<u32> = match socks5.to_str() {
        Ok(string) => match string.parse::<u32>() {
            Ok(result) => {
                if result == 0 {
                    None
                } else {
                    Some(result)
                }
            }
            Err(_) => {
                return S5Error::new(ErrorKind::Input, "Could not parse socks5 port to uint32")
                    .c_stringify()
            }
        },
        Err(_) => {
            return S5Error::new(ErrorKind::Input, "Could not convert socks5 port to String")
                .c_stringify()
        }
    };
    let social_root = CStr::from_ptr(social_root);
    let social_root: String = match social_root.to_str() {
        Ok(string) => string.to_string(),
        Err(_) => {
            return S5Error::new(ErrorKind::Input, "Could not convert social root to String")
                .c_stringify()
        }
    };
    let keypair = match ec::keypair_from_xprv_str(&social_root) {
        Ok(keypair) => keypair,
        Err(e) => return e.c_stringify(),
    };
    let xonly_pair = ec::XOnlyPair::from_keypair(keypair);

    match post::dto::last_derivation(hostname.clone(), socks5, xonly_pair.clone()) {
        Ok(last_index) => last_index.c_stringify(),
        Err(e) => return e.c_stringify(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::network::constants::Network;
    use std::ffi::{CStr, CString};
    #[test]
    // #[ignore]
    fn test_ffi_composite() {
        unsafe {
            //
            //
            // CREATE USER1 SOCIAL ROOT
            //
            //
            let seed = key::seed::MasterKeySeed::generate(12, "", Network::Bitcoin).unwrap();
            let master_xprv_cstr = CString::new(seed.xprv.to_string()).unwrap().into_raw();
            let account = "0";
            let account_cstr = CString::new(account).unwrap().into_raw();
            let result_ptr = create_social_root(master_xprv_cstr, account_cstr);
            let result_cstr = CStr::from_ptr(result_ptr);
            let result_str = result_cstr.to_str().unwrap();
            let ishi_child = key::child::SocialRoot::structify(result_str);
            assert!(ishi_child.is_ok());
            //
            //
            // CREATE USER2 SOCIAL ROOT
            //
            //
            let seed = key::seed::MasterKeySeed::generate(12, "", Network::Bitcoin).unwrap();
            let master_xprv_cstr = CString::new(seed.xprv.to_string()).unwrap().into_raw();
            let account = "0";
            let account_cstr = CString::new(account).unwrap().into_raw();
            let result_ptr = create_social_root(master_xprv_cstr, account_cstr);
            let result_cstr = CStr::from_ptr(result_ptr);
            let result_str = result_cstr.to_str().unwrap();
            let sushi_child = key::child::SocialRoot::structify(result_str);
            assert!(sushi_child.is_ok());
            //
            //
            // GET SERVER IDENTITY
            //
            //
            let hostname = "http://localhost:3021".to_string();
            let hostname_cstr = CString::new(hostname.clone()).unwrap().into_raw();
            let socks5 = "0";
            let socks5_cstr = CString::new(socks5).unwrap().into_raw();
            let ishi_social_root_cstr = CString::new(ishi_child.unwrap().xprv).unwrap().into_raw();
            let result_ptr = server_identity(hostname_cstr, socks5_cstr, ishi_social_root_cstr);
            let result_cstr = CStr::from_ptr(result_ptr);
            let result_str = result_cstr.to_str().unwrap();
            let server_id = identity::model::ServerIdentity::structify(result_str).unwrap();
            assert_eq!(server_id.kind, "PRIVATE".to_string());
            //
            //
            // ADMIN OPS (GET INVITE)
            //098f6bcd4621d373cade4e832627b4f6
            //9caff0735bc6e80121cedcb98ca51821
            let admin_secret = "098f6bcd4621d373cade4e832627b4f6";
            let admin_secret_cstr = CString::new(admin_secret).unwrap().into_raw();
            let kind = "priv";
            let kind_cstr = CString::new(kind).unwrap().into_raw();
            let count = "2";
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
            assert_eq!(invitation.invite_code.len(), 32);
            //
            //
            // REGISTER USER 1
            //
            //
            let nonce = key::encryption::nonce();
            let ishi_username = "ishii5".to_string() + &nonce[0..5].to_lowercase();
            let ishi_username_cstr = CString::new(ishi_username.clone()).unwrap().into_raw();
            let invite_code_cstr = CString::new(invitation.invite_code.clone())
                .unwrap()
                .into_raw();
            let result_ptr = join(
                hostname_cstr,
                socks5_cstr,
                ishi_social_root_cstr,
                ishi_username_cstr,
                invite_code_cstr,
            );
            let result_cstr = CStr::from_ptr(result_ptr);
            let result_str = result_cstr.to_str().unwrap();
            let invitation_detail =
                identity::model::InvitationDetail::structify(result_str).unwrap();
            assert_eq!(invitation_detail.invite_code.len(), 32);
            assert_eq!(invitation_detail.created_by, "ADMIN".to_string());
            //
            //
            // PRIV USER INVITE
            //
            //
            let sushi_social_root_cstr = CString::new(sushi_child.clone().unwrap().xprv)
                .unwrap()
                .into_raw();
            let invite_cstr = CString::new(invitation.invite_code.clone())
                .unwrap()
                .into_raw();
            let result_ptr = priv_user_invite(
                hostname_cstr,
                socks5_cstr,
                sushi_social_root_cstr.clone(),
                invite_cstr.clone(),
            );
            let result_cstr = CStr::from_ptr(result_ptr);
            let result_str = result_cstr.to_str().unwrap();
            let invitation = identity::model::Invitation::structify(result_str).unwrap();
            assert_eq!(invitation.invite_code.len(), 32);
            //
            //
            // REGISTER USER 2
            //
            //
            let nonce = key::encryption::nonce();
            let sushi_username = "sushii5".to_string() + &nonce[0..5].to_lowercase();
            let sushi_username_cstr = CString::new(sushi_username.clone()).unwrap().into_raw();
            let invite_code_cstr = CString::new(invitation.invite_code.clone())
                .unwrap()
                .into_raw();
            let result_ptr = join(
                hostname_cstr,
                socks5_cstr,
                sushi_social_root_cstr,
                sushi_username_cstr,
                invite_code_cstr,
            );
            let result_cstr = CStr::from_ptr(result_ptr);
            let result_str = result_cstr.to_str().unwrap();
            let invitation_detail =
                identity::model::InvitationDetail::structify(result_str).unwrap();
            assert_eq!(invitation_detail.invite_code.len(), 32);
            assert_eq!(invitation_detail.kind, "STANDARD".to_owned());
            //
            //
            // GET MEMBERS
            //
            //
            let result_ptr = get_members(hostname_cstr, socks5_cstr, ishi_social_root_cstr);
            let result_cstr = CStr::from_ptr(result_ptr);
            let result_str = result_cstr.to_str().unwrap();
            let members = identity::model::Members::structify(result_str);
            // println!("{:#?}",members.clone());
            assert!(members.clone().is_ok());
            //
            //
            // CREATE POST AS USER1
            //
            //
            let mut sushi_pubkey = "".to_string();
            for identity in members.clone().unwrap().identities {
                if identity.username == sushi_username {
                    sushi_pubkey = identity.pubkey.to_string();
                }
            }
            let to = "direct:".to_string() + &sushi_pubkey;
            let to_cstr = CString::new(to.clone()).unwrap().into_raw();
            let kind = "message".to_string();
            let kind_cstr = CString::new(kind.clone()).unwrap().into_raw();
            let value = "Hi sushi!".to_string();
            let value_cstr = CString::new(value.clone()).unwrap().into_raw();
            let index: u32 = 53;
            let index_cstr = CString::new(index.to_string()).unwrap().into_raw();
            let result_ptr = send_post(
                hostname_cstr,
                socks5_cstr,
                ishi_social_root_cstr,
                index_cstr,
                to_cstr,
                kind_cstr,
                value_cstr,
            );
            let result_cstr = CStr::from_ptr(result_ptr);
            let result_str = result_cstr.to_str().unwrap();
            let post_id = post::model::PostId::structify(result_str);
            assert!(post_id.is_ok());
            //
            //
            // SEND KEYS TO USER2
            //
            //
            let recipients = &sushi_pubkey;
            let recipients_cstr = CString::new(recipients.clone()).unwrap().into_raw();
            let post_id_cstr = CString::new(post_id.unwrap().id).unwrap().into_raw();
            let result_ptr = send_keys(
                hostname_cstr,
                socks5_cstr,
                ishi_social_root_cstr,
                index_cstr,
                post_id_cstr,
                recipients_cstr,
            );
            let result_cstr = CStr::from_ptr(result_ptr);
            let result_str = result_cstr.to_str().unwrap();
            let response = network::handler::ServerStatusResponse::structify(result_str).unwrap();
            assert!(response.status);
            //
            //
            // GET ONE POST AS USER1
            //
            //
            let result_ptr = get_one_post(
                hostname_cstr,
                socks5_cstr,
                ishi_social_root_cstr,
                post_id_cstr,
            );
            let result_cstr = CStr::from_ptr(result_ptr);
            let result_str = result_cstr.to_str().unwrap();
            let post = post::model::LocalPostModel::structify(result_str);
            assert!(post.is_ok());
            assert_eq!(post.unwrap().post.payload.value, value);
            //
            //
            // CREATE POST AS USER2
            //
            //
            let mut ishi_pubkey = "".to_string();
            for identity in members.clone().unwrap().identities {
                if identity.username == ishi_username {
                    ishi_pubkey = identity.pubkey.to_string();
                }
            }
            let to = "direct:".to_string() + &ishi_pubkey;
            let to_cstr = CString::new(to.clone()).unwrap().into_raw();
            let kind = "message".to_string();
            let kind_cstr = CString::new(kind.clone()).unwrap().into_raw();
            let value = "Hi ishi!".to_string();
            let value_cstr = CString::new(value.clone()).unwrap().into_raw();
             let index: u32 = 53;
            let index_cstr = CString::new(index.to_string()).unwrap().into_raw();
            let result_ptr = send_post(
                hostname_cstr,
                socks5_cstr,
                sushi_social_root_cstr,
                index_cstr,
                to_cstr,
                kind_cstr,
                value_cstr,
            );
            let result_cstr = CStr::from_ptr(result_ptr);
            let result_str = result_cstr.to_str().unwrap();
            let post_id = post::model::PostId::structify(result_str);
            assert!(post_id.is_ok());
            //
            //
            // SEND KEYS TO USER1
            //
            //
            let recipients = &ishi_pubkey;
            let recipients_cstr = CString::new(recipients.clone()).unwrap().into_raw();
            let post_id_cstr = CString::new(post_id.unwrap().id).unwrap().into_raw();
            let result_ptr = send_keys(
                hostname_cstr,
                socks5_cstr,
                sushi_social_root_cstr,
                index_cstr,
                post_id_cstr,
                recipients_cstr,
            );
            let result_cstr = CStr::from_ptr(result_ptr);
            let result_str = result_cstr.to_str().unwrap();
            let response = network::handler::ServerStatusResponse::structify(result_str).unwrap();
            assert!(response.status);
            //
            //
            // GET ALL POSTS AS USER2
            //
            //
            let filter: u64 = 0;
            let filter_cstr = CString::new(filter.to_string()).unwrap().into_raw();

            let result_ptr = get_all_posts(
                hostname_cstr,
                socks5_cstr,
                sushi_social_root_cstr,
                filter_cstr,
            );
            let result_cstr = CStr::from_ptr(result_ptr);
            let result_str = result_cstr.to_str().unwrap();
            // println!("{result_str}");
            let all_posts = post::model::SortedPosts::structify(result_str);
            assert!(all_posts.is_ok());

            let mem_len = members.clone().unwrap().identities.len();
            let user1 = &members.clone().unwrap().identities[mem_len - 2]; // we want the second last user

            let all_posts_len = all_posts.clone().unwrap().verified[0].posts.len();
            assert_eq!(
                all_posts.clone().unwrap().verified[0].counter_party,
                user1.pubkey.to_string()
            );
            assert_eq!(
                all_posts.clone().unwrap().verified[0].posts[all_posts_len - 1]
                    .post
                    .payload
                    .value,
                value
            ); // we compare the last post payload value
            assert!(all_posts.clone().unwrap().corrupted.last().is_none());
            assert_eq!(
                all_posts.clone().unwrap().latest_genesis,
                all_posts.clone().unwrap().verified[0].posts[all_posts_len - 1].genesis
            ); // we compare against the last post
               //
               //
               // GET LAST INDEX AS USER1
               //
               //
            let result_ptr = last_index(hostname_cstr, socks5_cstr, ishi_social_root_cstr);
            let result_cstr = CStr::from_ptr(result_ptr);
            let result_str = result_cstr.to_str().unwrap();
            // print!("{result_str}");
            let derivation_index = post::model::DerivationIndex::structify(result_str);
            assert!(derivation_index.is_ok());
            assert_eq!(derivation_index.unwrap().last_used, index);
            //
            //
            // LEAVE USER1
            //
            //
            let result_ptr = leave(hostname_cstr, socks5_cstr, ishi_social_root_cstr);
            let result_cstr = CStr::from_ptr(result_ptr);
            let result_str = result_cstr.to_str().unwrap();
            let response = network::handler::ServerStatusResponse::structify(result_str).unwrap();
            assert!(response.status);
            //
            //
            // LEAVE USER2
            //
            //
            let result_ptr = leave(hostname_cstr, socks5_cstr, sushi_social_root_cstr);
            let result_cstr = CStr::from_ptr(result_ptr);
            let result_str = result_cstr.to_str().unwrap();
            let response = network::handler::ServerStatusResponse::structify(result_str).unwrap();
            assert!(response.status);
        }
    }
}
