use std::error;
use std::fmt;

// TODO Build our specific DkCryptoError for the project

#[derive(Debug, Clone)]
pub struct DkCryptoError;

impl fmt::Display for DkCryptoError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "")
    }
}

impl error::Error for DkCryptoError {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        None
    }
}