use curve25519_dalek::Scalar;

pub const SECRET_SIZE: usize = 104;

pub struct UtxoSecrets {
    pub spending_secret: [u8; 32],
    pub nullifier_secret: [u8; 32],
    pub amount: u64,
    pub tweak_scalar: Scalar,
}

impl From<[u8; SECRET_SIZE]> for UtxoSecrets {
    fn from(bytes: [u8; SECRET_SIZE]) -> Self {
        let mut spending_secret = [0u8; 32];
        let mut nullifier_secret = [0u8; 32];

        spending_secret.copy_from_slice(&bytes[0..32]);
        nullifier_secret.copy_from_slice(&bytes[32..64]);
        let amount = u64::from_be_bytes(bytes[64..72].try_into().unwrap());
        let tweak_scalar = Scalar::from_bytes_mod_order(bytes[72..104].try_into().unwrap());

        Self {
            spending_secret,
            nullifier_secret,
            amount,
            tweak_scalar,
        }
    }
}

impl From<UtxoSecrets> for [u8; SECRET_SIZE] {
    fn from(secret: UtxoSecrets) -> Self {
        let mut bytes = [0u8; SECRET_SIZE];
        bytes[0..32].copy_from_slice(&secret.spending_secret);
        bytes[32..64].copy_from_slice(&secret.nullifier_secret);
        bytes[64..72].copy_from_slice(&secret.amount.to_be_bytes());
        bytes[72..104].copy_from_slice(&secret.tweak_scalar.to_bytes());
        bytes
    }
}
