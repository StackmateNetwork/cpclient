use crate::lib::sleddb;
use crate::lib::e::{ErrorKind, S5Error};
use crate::network::identity::model::{MemberIdentity,UserIdentity};
use bitcoin::secp256k1::{XOnlyPublicKey};
use std::str;

pub fn create_members(host: String, member_models: Vec<MemberIdentity>)->Result<bool, S5Error>{
    let db = sleddb::get_root(sleddb::LotrDatabase::Members, Some(host)).unwrap();
    let main_tree = sleddb::get_tree(db, "members").unwrap();
    let bytes = bincode::serialize(&member_models).unwrap();
    main_tree.insert("0", bytes).unwrap();
    Ok(true)
}
pub fn read_all_members(host: String)->Result<Vec<MemberIdentity>,S5Error>{
    let db = sleddb::get_root(sleddb::LotrDatabase::Members, Some(host)).unwrap();
    match sleddb::get_tree(db.clone(), "members"){
        Ok(tree)=>{
            if tree.contains_key(b"0").unwrap() {
            match tree.get("0").unwrap() {
                Some(bytes) => {
                    let members: Vec<MemberIdentity> = bincode::deserialize(&bytes).unwrap();
                    tree.flush().unwrap();
                    Ok(members)
                },
                None => Err(S5Error::new(ErrorKind::Internal, "No AllMembers found in members tree"))
            }
            } else {
                db.drop_tree(&tree.name()).unwrap();
                tree.flush().unwrap();
                Err(S5Error::new(ErrorKind::Input, "No such index found in members tree"))
            }
        }
        Err(_)=>{
            Err(S5Error::new(ErrorKind::Internal, "Could not get members tree"))
        }
    }

}
pub fn get_username_by_pubkey(mut members: Vec<MemberIdentity>, pubkey: XOnlyPublicKey)->Result<String,S5Error>{
    members.retain(|val| val.pubkey == pubkey);
    if members.len() == 1 {
        Ok(members[0].username.to_string())
    }
    else if members.len() > 0 {// should never reach here
        Err(S5Error::new(ErrorKind::Input, "Duplicate member found with this pubkey."))
    }
    else  { 
        Err(S5Error::new(ErrorKind::Input, "No member found with this pubkey."))
    }

}
pub fn delete_members(host: String)->bool{
    let db = sleddb::get_root(sleddb::LotrDatabase::Members, Some(host)).unwrap();
    let tree = sleddb::get_tree(db.clone(), "members").unwrap();
    tree.clear().unwrap();
    tree.flush().unwrap();
    db.drop_tree(&tree.name()).unwrap();
    true
}

pub fn create_my_identity(host: String, user: UserIdentity, password: String)->Result<bool, S5Error>{
    let entry = user.clone().encrypt(password);
    let db = sleddb::get_root(sleddb::LotrDatabase::Identity,Some(host)).unwrap();
    let main_tree = sleddb::get_tree(db, &user.username).unwrap();
    main_tree.insert("0", entry.as_bytes()).unwrap();
    Ok(true)
}
pub fn read_my_identity(host: String, username: String, password: String)->Result<UserIdentity,S5Error>{
    let db = sleddb::get_root(sleddb::LotrDatabase::Identity,Some(host)).unwrap();
    match sleddb::get_tree(db.clone(), &username){
        Ok(tree)=>{
            if tree.contains_key(b"0").unwrap() {
            match tree.get("0").unwrap() {
                Some(bytes) => {
                    let user = match UserIdentity::decrypt(std::str::from_utf8(&bytes).unwrap().to_string(),password){
                        Ok(user)=>user,
                        Err(e)=>return Err(e)
                    };
                    Ok(user)
                },
                None => Err(S5Error::new(ErrorKind::Internal, "No UserIdentity found in me tree"))
            }
            } else {
                db.drop_tree(&tree.name()).unwrap();
                tree.flush().unwrap();
                Err(S5Error::new(ErrorKind::Input, "No such index found in me tree"))
            }
        }
        Err(_)=>{
            Err(S5Error::new(ErrorKind::Internal, "Could not get me tree"))
        }
    }
}

pub fn delete_my_identity(host: String, username: String)->bool{
    let db = sleddb::get_root(sleddb::LotrDatabase::Identity,Some(host)).unwrap();
    let tree = sleddb::get_tree(db.clone(), &username).unwrap();
    tree.clear().unwrap();
    tree.flush().unwrap();
    db.drop_tree(&tree.name()).unwrap();
    true
}

pub fn get_username_indexes(host: String) -> Vec<String>{
    let root = sleddb::get_root(sleddb::LotrDatabase::Identity,Some(host)).unwrap();
    let mut usernames: Vec<String> = [].to_vec();
    for key in root.tree_names().iter() {
        let username = str::from_utf8(key).unwrap();
        if username.starts_with("__"){
        }
        else{
            usernames.push(username.to_string());
        };
    }
    usernames
}
#[cfg(test)]
mod tests {
  use super::*;
  use crate::key::ec;
  use crate::key::seed;
  use crate::key::child;
  use bdk::bitcoin::network::constants::Network;

  #[test]
  fn test_identity_store(){
    let seed1 = seed::generate(24, "", Network::Bitcoin).unwrap();
    let social_child1 = child::to_path_str(seed1.xprv, "m/128h/0h").unwrap();
    
    let me = UserIdentity{
        username: "ishi".to_string(),
        account: 0,
        social_root: social_child1.xprv,
        last_path: "m/1/23".to_string(),
    };
    let password = "secret".to_string();

    let host = "localhost".to_string();

    let mem1 = MemberIdentity{
        username: "sushi".to_string(),
        pubkey: ec::pubkey_from_str("2ad4b769ddfdd8e47cb4840d85b679ad17d2f076b2ca65b6f18758db41257ccc").unwrap()
    };
    let mem2 = MemberIdentity{
        username: "bubble".to_string(),
        pubkey: ec::pubkey_from_str("1585c9ac1392819d93003fa3634274463c88982f6053bc53dada159093012a3f").unwrap()
    };
    let status = create_my_identity(host.clone(),me.clone(), password.clone()).unwrap();
    assert!(status);

    let my_identity = read_my_identity(host.clone(),me.clone().username, password).unwrap();
    assert_eq!(my_identity.username,me.username);

    let status = create_members(host.clone(),[me.to_member_id(),mem1,mem2.clone()].to_vec()).unwrap();
    assert!(status);
    let members = read_all_members(host.clone()).unwrap();
    assert_eq!(members.len(),3);

    let member = get_username_by_pubkey(members,ec::pubkey_from_str("1585c9ac1392819d93003fa3634274463c88982f6053bc53dada159093012a3f").unwrap()).unwrap();    
    assert_eq!(member, mem2.username);

    let status = delete_members(host.clone());
    assert!(status);
  }
}