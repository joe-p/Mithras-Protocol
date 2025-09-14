uniffi::setup_scaffolding!();

#[derive(uniffi::Error, Debug)]
pub enum MithrasCryptoError {
    Error(String),
}

impl std::fmt::Display for MithrasCryptoError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            MithrasCryptoError::Error(msg) => write!(f, "MithrasCryptoError: {}", msg),
        }
    }
}

mod address;
mod hpke;
mod utxo;
