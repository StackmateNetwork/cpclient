use tungstenite::{connect};
use tungstenite::protocol::WebSocket;
use tungstenite::stream::MaybeTlsStream;
use std::net::TcpStream;
use http::{Request};
use crate::key::encryption::{nonce};
use crate::key::ec::{XOnlyPair};
use crate::network::handler::{HttpHeader,HttpMethod,APIEndPoint, sign_request};
use crate::lib::e::{ErrorKind, S5Error};

pub fn sync(host: &str, key_pair: XOnlyPair)->Result<WebSocket<MaybeTlsStream<TcpStream>>,S5Error>{
    let full_url = host.to_string() + &APIEndPoint::Notifications.to_string();
    let random_string = nonce();
    let signature = sign_request(key_pair.clone(), HttpMethod::Get, APIEndPoint::Notifications, &random_string).unwrap();
    let request = match Request::builder()
        // .method("GET")
        .uri(full_url)
        .header(&HttpHeader::Signature.to_string(), &signature)
        .header(&HttpHeader::Pubkey.to_string(), &key_pair.pubkey.to_string())
        .header(&HttpHeader::Nonce.to_string(), &random_string)
        .body(()){
            Ok(result)=>result,
            Err(_)=>return Err(S5Error::new(ErrorKind::Input, "Error Building Socket Request"))
        };
    let (socket, _) = match connect(
        request
    ){
        Ok((socket,response))=>(socket,response),
        Err(_)=>return Err(S5Error::new(ErrorKind::Network, "Error Connecting!"))
    };
    Ok(socket)
}


#[cfg(test)]
mod tests {
    use super::*;
    use crate::key::seed;
    use bitcoin::network::constants::Network;
    use crate::network::identity::dto::{admin_invite,register,get_all,remove};
    use tungstenite::{Message};

    #[test] 
    #[ignore]
    fn test_notifications_dto(){
        // FIRST INVITE THE GUY
        let host = "http://localhost:3021";
        // ADMIN INVITE
        let admin_invite_code = "098f6bcd4621d373cade4e832627b4f6";
        let client_invite_code = admin_invite(host,admin_invite_code).unwrap();
        assert_eq!(client_invite_code.len() , 32);
        // REGISTER USER
        let seed = seed::generate(24, "", Network::Bitcoin).unwrap();
        let key_pair = XOnlyPair::from_xprv(seed.xprv);
        let random_string = nonce();
        let username = "ishi".to_string() + &random_string[0..5];
        register(host, key_pair.clone(), &client_invite_code, &username).unwrap();
        
        // GET ALL USERS
        let identities = get_all(host, key_pair.clone()).unwrap();
        let user_count = identities.len();
        assert!(user_count>0);
        let ws_host = "ws://localhost:3021";
        let mut socket = sync(ws_host, key_pair.clone()).unwrap();
        socket.write_message(Message::Text("connection".into())).unwrap();
        // loop {
        //     let msg = socket.read_message().expect("Error reading message");
        //     println!("{}", msg);
        // }
        // REMOVE THE GUY
        remove(host, key_pair).unwrap();
    }
    
}

