use std::fmt::Debug;
use std::time::Duration;
use std::{collections::HashMap, sync::Arc};

use chrono::{DateTime, NaiveDateTime, Utc};
//
// google.rs
// Copyright (C) 2022 matthew <matthew@WINDOWS-05HIC4F>
// Distributed under terms of the MIT license.
//
use jwt::PKeyWithDigest;
use jwt::{Header, Store, Token, Verified};
use openssl::hash::MessageDigest;
use openssl::pkey::{PKey, Public};
use openssl::x509::X509;
use reqwest::header::HeaderMap;
use rocket::tokio::sync::OnceCell;
use rocket::{data::FromData, form::Form, http::Status, outcome::try_outcome, Data, FromForm};
use serde::Deserialize;

pub struct GoogleToken {
    token: Token<Header, Gc, Verified>,
}

impl GoogleToken {
    /// Gets the assigned email type
    pub fn email(&self) -> &str {
        &self.token.claims().email
    }

    /// Whether Google has verified the user's email.
    pub fn email_verified(&self) -> bool {
        self.token.claims().email_verified
    }

    /// Unique Google id
    pub fn google_id(&self) -> &str {
        &self.token.claims().sub
    }

    /// User's full name
    pub fn full_name(&self) -> &str {
        &self.token.claims().name
    }

    /// User's given name. This corresponds to a European first name, suitable for informal address
    pub fn given_name(&self) -> &str {
        &self.token.claims().given_name
    }

    /// User's family name. This corresponds to a European last name. This is suitable for more
    /// formal address, although it should be noted that `full_name` is preferable when the User's
    /// full name is desired
    pub fn family_name(&self) -> &str {
        &self.token.claims().family_name
    }

    /// Unique id of this token
    #[allow(unused)]
    fn id(&self) -> &str {
        &self.token.claims().jti
    }
}

impl Debug for GoogleToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self.token.claims())
    }
}

struct KeyStore<'a>(flurry::HashMapRef<'a, String, PKeyWithDigest<Public>>);

impl<'a> Store for KeyStore<'a> {
    type Algorithm = PKeyWithDigest<Public>;

    fn get(&self, key_id: &str) -> Option<&Self::Algorithm> {
        self.0.get(key_id)
    }
}

#[derive(Clone)]
pub(crate) struct GoogleState {
    client_id: Arc<OnceCell<String>>,
    keys: Arc<flurry::HashMap<String, PKeyWithDigest<Public>>>,
}

impl GoogleState {
    pub(crate) fn new(client_id: Arc<OnceCell<String>>) -> Self {
        Self {
            client_id,
            keys: Arc::new(flurry::HashMap::new()),
        }
    }

    fn sleep_duration(headers: &HeaderMap) -> Duration {
        let age = headers
            .get("age")
            .and_then(|s| s.to_str().ok())
            .and_then(|s| s.parse().ok())
            .unwrap_or(0);
        let max_age = headers
            .get("cache-control")
            .and_then(|s| s.to_str().ok())
            .and_then(|s| s.split(',').find(|s| s.trim().starts_with("max-age")))
            .and_then(|s| s.split_once("=").and_then(|(_, n)| n.trim().parse().ok()))
            .unwrap_or(1);
        if max_age > age + 3 {
            Duration::from_secs(max_age - age - 2)
        } else {
            Duration::from_secs(1)
        }
    }

    pub(crate) async fn update(&self) {
        loop {
            if let Ok(tmp) = reqwest::get("https://www.googleapis.com/oauth2/v1/certs").await {
                if tmp.status().is_success() {
                    let sleep = Self::sleep_duration(tmp.headers());
                    if let Ok(res) = tmp.json::<HashMap<String, String>>().await {
                        let guard = self.keys.guard();
                        self.keys.clear(&guard);
                        for (k, v) in res {
                            println!("Grabbed key: {} = {}", k, v);
                            let value = PKeyWithDigest {
                                digest: MessageDigest::sha256(), // TODO: check this is correct
                                key: X509::from_pem(v.as_bytes())
                                    .expect("Malformed key from Google's server")
                                    .public_key()
                                    .expect("Malformed key from Google's server"),
                                //key: PKey::public_key_from_pem(v.as_bytes())
                                //.expect("Malformed key from Google's server"),
                            };
                            self.keys.insert(k, value, &guard);
                        }
                    }
                    rocket::tokio::time::sleep(sleep).await;
                }
            }
        }
    }
}

#[derive(Debug, Deserialize, FromForm)]
struct GoogleTokenData<'r> {
    credential: &'r str,
    g_csrf_token: &'r str,
}

#[derive(Debug)]
pub enum TokenError<'r> {
    FormError(rocket::form::Errors<'r>),
    TokenError(jwt::Error),
    InvalidToken(&'static str),
}

#[derive(Debug, Deserialize)]
struct Gc {
    /// Issuer (i.e. accounts.google.com)
    iss: String,
    /// Not Before (unix) normally we can ignore this
    nbf: UnixStamp,
    /// Our client ID
    aud: String,
    /// Unique Google ID of the user
    sub: String,
    /// Host domain of the user's GSuite email address
    /// Note that this is typically None for Gmail addresses
    hd: Option<String>,
    /// User's email address
    email: String,
    /// Has Google verified the email address. My understanding is that Gmail addresses are
    /// automatically verified, and they have some process to verify external email addresses.
    /// Overall, I think we can trust this.
    email_verified: bool,
    /// I don't know. This may be a repeat of `aud`
    azp: String,
    /// User's Name. I suspect this is what we should use when asked for a name
    name: String,
    /// If present, a URL to user's profile picture
    picture: Option<String>,
    /// This is the first name (i.e. for informal address)
    given_name: String,
    /// This is the last name (i.e. for formal address)
    family_name: String,
    /// Creation time (unix)
    iat: UnixStamp, // Unix timestamp of the assertion's creation time
    /// Expiration time (unix)
    exp: UnixStamp, // Unix timestamp of the assertion's expiration time
    /// Unique identifier of the token. Every token has a different value here.
    jti: String,
}

#[derive(Debug, Deserialize)]
#[serde(from = "i64")]
struct UnixStamp(DateTime<Utc>);

impl From<i64> for UnixStamp {
    fn from(t: i64) -> Self {
        Self(DateTime::from_utc(NaiveDateTime::from_timestamp(t, 0), Utc))
    }
}

impl UnixStamp {
    pub fn time(&self) -> &DateTime<Utc> {
        &self.0
    }
}

#[rocket::async_trait]
impl<'r> FromData<'r> for GoogleToken {
    type Error = TokenError<'r>;

    async fn from_data(
        r: &'r rocket::Request<'_>,
        data: Data<'r>,
    ) -> rocket::data::Outcome<'r, Self, Self::Error> {
        use jwt::VerifyWithStore;
        let token = try_outcome!(Form::<GoogleTokenData<'r>>::from_data(r, data)
            .await
            .map_failure(|(s, e)| (s, TokenError::FormError(e))));
        if Some(token.g_csrf_token) != r.cookies().get("g_csrf_token").map(|c| c.value()) {
            rocket::outcome::Outcome::Failure((
                Status::BadRequest,
                TokenError::InvalidToken("Cross Site Request Forgery Token was not valid"),
            ))
        } else {
            let state: &GoogleState = r.rocket().state().expect("AuthFairing is required");
            let guard = state.keys.guard();
            let key_store = KeyStore(state.keys.with_guard(&guard));
            match token.credential.verify_with_store(&key_store) {
                Ok(token) => {
                    let token: Token<Header, Gc, _> = token;
                    if token
                        .claims()
                        .iss
                        .strip_prefix("https://")
                        .unwrap_or(&token.claims().iss)
                        != "accounts.google.com"
                    {
                        return rocket::outcome::Outcome::Failure((
                            Status::BadRequest,
                            TokenError::InvalidToken("Invalid Issuer"),
                        ));
                    }
                    if &token.claims().aud != state.client_id.get().unwrap() {
                        return rocket::outcome::Outcome::Failure((
                            Status::BadRequest,
                            TokenError::InvalidToken("Wrong client id"),
                        ));
                    }
                    if token.claims().exp.time() > &Utc::now() {
                        return rocket::outcome::Outcome::Failure((
                            Status::BadRequest,
                            TokenError::InvalidToken("Token expired"),
                        ));
                    }
                    if token.claims().nbf.time() < &Utc::now() {
                        return rocket::outcome::Outcome::Failure((
                            Status::BadRequest,
                            TokenError::InvalidToken("Token not valid yet"),
                        ));
                    }
                    rocket::outcome::Outcome::Success(Self { token })
                }
                Err(e) => rocket::outcome::Outcome::Failure((
                    Status::BadRequest,
                    TokenError::TokenError(e),
                )),
            }
        }
    }
}
