// Implement bitcoin and bdk error type.
use std::fmt::Display;
use std::fmt::Formatter;
use serde::{Deserialize, Serialize};


#[derive(Serialize, Deserialize, Debug, Copy, Clone)]
pub enum ErrorKind {
  Key,
  Wallet,
  Network,
  Input,
  NoResource,
  Internal,
}

impl Display for ErrorKind {
  fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
    match self {
      ErrorKind::Input => write!(f, "Input"),
      ErrorKind::Internal => write!(f, "OpError"),
      ErrorKind::Key => write!(f, "KeyError"),
      ErrorKind::Wallet => write!(f, "WalletError"),
      ErrorKind::Network => write!(f, "NetworkError"),
      ErrorKind::NoResource => write!(f, "NoResourceFound"),

    }
  }
}

impl PartialEq for ErrorKind {
  fn eq(&self,rs: &ErrorKind) -> bool {
    self.to_string() == rs.to_string()
  }
}


#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct S5Error {
  pub kind: String,
  pub message: String,
}

impl S5Error {
  pub fn new(kind: ErrorKind, message: &str) -> Self {
    S5Error {
      kind: kind.to_string(),
      message: message.to_string(),
    }
  }
  pub fn from_ureq(e: ureq::Error)->Self{
    match e {
      ureq::Error::Status(code, response) => {
        let kind = match code {
            400 => ErrorKind::Input,
            401 => ErrorKind::Key,
            403 => ErrorKind::Key,
            404 => ErrorKind::NoResource,
            409 => ErrorKind::Input,
            _=> ErrorKind::Internal
        };
        S5Error::new(kind, &response.into_string().unwrap())
      }
      _ => { 
        S5Error::new(ErrorKind::Network, "Transport Error. Check your internet connection AND/OR your request object.")
      }
    }
  }

}