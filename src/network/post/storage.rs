use crate::lib::sleddb;
use crate::lib::e::{ErrorKind, S5Error};
use crate::network::model::{LocalPostModel};

pub fn create_posts(host: String,post_models: Vec<LocalPostModel>, username: String)->Result<bool, S5Error>{
    let db = sleddb::get_root(sleddb::LotrDatabase::Network,Some(host)).unwrap();
    let main_tree = sleddb::get_tree(db, "posts").unwrap();
    let bytes = bincode::serialize(&post_models).unwrap();
    main_tree.insert(&username.to_string(), bytes).unwrap();
    Ok(true)
}
pub fn read_posts(host: String,username: String)->Result<Vec<LocalPostModel>,S5Error>{
    let db = sleddb::get_root(sleddb::LotrDatabase::Networ,Some(host)).unwrap();
    match sleddb::get_tree(db.clone(), "posts"){
        Ok(tree)=>{
            if tree.contains_key(&username.as_bytes()).unwrap() {
            match tree.get(&username).unwrap() {
                Some(bytes) => {
                    let posts: AllPosts = bincode::deserialize(&bytes).unwrap();
                    tree.flush().unwrap();
                    Ok(posts)
                },
                None => Err(S5Error::new(ErrorKind::Internal, "No AllPosts found in posts tree"))
            }
            } else {
                db.drop_tree(&tree.name()).unwrap();
                tree.flush().unwrap();
                Err(S5Error::new(ErrorKind::Input, "No such index found in posts tree"))
            }
        }
        Err(_)=>{
            Err(S5Error::new(ErrorKind::Internal, "Could not get posts tree"))
        }
    }

}
pub fn delete_posts(host: String,username: String)->(){
    let db = sleddb::get_root(sleddb::LotrDatabase::Network,Some(host)).unwrap();
    let tree = sleddb::get_tree(db.clone(), "posts").unwrap();
    tree.clear().unwrap();
    tree.flush().unwrap();
    ()
}

#[cfg(test)]
mod tests {
  use super::*;
  use crate::network::model::{LocalPostModel,PlainPost,PostItem};

  #[test]
  fn test_posts_store() {

  }
  

}