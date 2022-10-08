use crate::lib::sleddb;
use crate::lib::e::{ErrorKind, S5Error};
use crate::key::seed::{MasterKeySeed};
use bdk::bitcoin::network::constants::Network;

pub fn create_keys(password: String, master: MasterKeySeed, network: Network)->Result<(), S5Error>{
    let db = sleddb::get_root(sleddb::LotrDatabase::MasterKey,Some(network.to_string())).unwrap();
    let main_tree = sleddb::get_tree(db, "keys").unwrap();
    let cipher = master.encrypt(&password);
    main_tree.insert("0", cipher.as_bytes()).unwrap();
    Ok(())
}
pub fn read_keys(password: String, network: Network)->Result<MasterKeySeed, S5Error>{
    let db = sleddb::get_root(sleddb::LotrDatabase::MasterKey,Some(network.to_string())).unwrap();
    match sleddb::get_tree(db.clone(), "keys"){
        Ok(tree)=>{
            if tree.contains_key(b"0").unwrap() {
            match tree.get("0").unwrap() {
                Some(bytes) => {
                    let master = match MasterKeySeed::decrypt(std::str::from_utf8(&bytes).unwrap().to_string(),password){
                        Ok(value)=>value,
                        Err(e)=>return Err(e)
                    };
                    Ok(master)
                },
                None => Err(S5Error::new(ErrorKind::Internal, "No MasterKeySeed found in key tree"))
            }
            } else {
            db.drop_tree(&tree.name()).unwrap();
                Err(S5Error::new(ErrorKind::Input, "No index found in key tree"))
            }
        }
        Err(_)=>{
            Err(S5Error::new(ErrorKind::Internal, "Could not get key tree"))
        }
    }
}
pub fn delete_keys(network: Network)->bool{
    let db = sleddb::get_root(sleddb::LotrDatabase::MasterKey,Some(network.to_string())).unwrap();
    let tree = sleddb::get_tree(db.clone(), "keys").unwrap();
    tree.clear().unwrap();
    tree.flush().unwrap();
    db.drop_tree(&tree.name()).unwrap();
    true
}

#[cfg(test)]
mod tests {
  use super::*;
  use crate::key::seed;
  use crate::key::child;
  use bdk::bitcoin::network::constants::Network;

  #[test]
  fn test_master_key_storage() {

  }

}