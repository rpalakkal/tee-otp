use rand::Rng;
use totp_rs::{Algorithm, Secret};

pub struct TOTP {
    secret: String,
    account_id: String,
}

impl TOTP {
    fn totp(&self) -> totp_rs::TOTP {
        totp_rs::TOTP::new(
            Algorithm::SHA1,
            6,
            1,
            30,
            Secret::Encoded(self.secret.clone()).to_bytes().unwrap(),
            Some("tee-otp".to_string()),
            self.account_id.clone(),
        )
        .unwrap()
    }

    pub fn from_secret(account_id: String, secret: String) -> Self {
        Self { secret, account_id }
    }

    pub fn random(account_id: String) -> Self {
        let mut rng = rand::thread_rng();
        let bytes: [u8; 21] = rng.gen();
        let secret = base32::encode(base32::Alphabet::Rfc4648 { padding: false }, &bytes);
        Self::from_secret(account_id, secret)
    }

    pub fn secret(&self) -> String {
        self.secret.clone()
    }

    pub fn qr(&self) -> String {
        self.totp().get_qr_base64().unwrap()
    }

    pub fn verify(&self, token: String) -> bool {
        self.totp().check_current(&token).unwrap()
    }
}
