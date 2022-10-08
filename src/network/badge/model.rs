use serde::{Deserialize, Serialize};
use bitcoin::secp256k1::{XOnlyPublicKey};
use crate::key::ec::{XOnlyPair,xonly_to_public_key, schnorr_verify};
use bdk::bitcoin::secp256k1::schnorr::Signature;
use crate::network::handler::{AnnouncementType};
use crate::key::encryption::{nonce};

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Badge{
    pub genesis: Option<u64>,
    pub kind: AnnouncementType,
    pub by: XOnlyPublicKey,
    pub to : XOnlyPublicKey,
    pub nonce: String,
    pub signature: Signature,
    pub hash: Option<String>
}

impl Badge {
    pub fn new(
        kind: AnnouncementType,
        creator: XOnlyPair,
        to: XOnlyPublicKey,
    )->Self{
        let nonce = nonce();
        let message = format!("{}:{}:{}:{}",creator.pubkey.to_string(),to.to_string(),kind.to_string(),nonce);
        let signature = creator.schnorr_sign(&message).unwrap();
        Badge{
            genesis: None,
            kind,
            by:creator.pubkey,
            to,
            nonce,
            signature,
            hash: None
        }
    }

    pub fn verify(&self)->bool{
        let message = format!("{}:{}:{}:{}",self.by.to_string(),self.to.to_string(),self.kind.to_string(),self.nonce);
        schnorr_verify(self.signature,&message,self.by).is_ok()
    }
}

