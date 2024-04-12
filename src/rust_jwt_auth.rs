use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};
use std::time::SystemTime;

#[derive(Debug, Serialize, Deserialize)]
struct Claims {
    sub: String,
    exp: usize,
    refresh_exp: usize,
}

pub fn generate_tokens(secret: &str, subject: &str, expiration_secs: u64, refresh_secs: u64) -> (String, String) {
    let current_time = SystemTime::now();
    let expiration = current_time
        .checked_add(Duration::from_secs(expiration_secs))
        .unwrap()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as usize;

    let refresh_exp = current_time
        .checked_add(Duration::from_secs(refresh_secs))
        .unwrap()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as usize;

    let claims = Claims {
        sub: subject.to_owned(),
        exp: expiration,
        refresh_exp: refresh_exp,
    };

    let access_token = encode(&Header::default(), &claims, &EncodingKey::from_secret(secret.as_ref())).unwrap();
    
    let refresh_token = generate_refresh_token(secret, subject, refresh_secs);

    (access_token, refresh_token)
}

fn generate_refresh_token(secret: &str, subject: &str, expiration_secs: u64) -> String {
    let expiration = SystemTime::now()
        .checked_add(Duration::from_secs(expiration_secs))
        .unwrap()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as usize;

    let claims = Claims {
        sub: subject.to_owned(),
        exp: expiration,
        refresh_exp: 0,
    };

    encode(&Header::default(), &claims, &EncodingKey::from_secret(secret.as_ref())).unwrap()
}

pub fn verify_token(secret: &str, token: &str) -> Option<String> {
    match decode::<Claims>(
        token,
        &DecodingKey::from_secret(secret.as_ref()),
        &Validation::default(),
    ) {
        Ok(token_data) => {
            if token_data.claims.exp >= SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() as usize {
                Some(token_data.claims.sub)
            } else {
                None
            }
        }
        Err(_) => None,
    }
}
