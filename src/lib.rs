use std::{
    borrow::Cow,
    fmt::{Debug, Display},
    hash::Hash,
    marker::PhantomData,
    str::FromStr,
    sync::Arc,
};

use flurry::Guard;
use rand::Rng;
use rocket::{
    fairing::{Fairing, Info, Kind},
    form::{self, FromFormField, ValueField},
    http::{Cookie, CookieJar},
    request::{FromRequest, Outcome},
    Orbit, Request, Rocket, Sentinel,
};

use chrono::{DateTime, Utc};
use sha2::{Digest, Sha256};

//#[cfg(feature = "serde")]
use ::serde::{Deserialize, Serialize};

//#[cfg(feature = "serde")]
//mod serde;
//#[cfg(feature = "diesel")]
mod diesel;

const TOKEN_COOKIE: &str = "client_token";

#[derive(Debug, Hash, PartialEq, Eq)]
//#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Serialize, Deserialize)]
#[serde(transparent)]
pub struct UserId<'a>(pub Cow<'a, str>);

impl<'v> FromFormField<'v> for UserId<'v> {
    fn from_value(field: ValueField<'v>) -> form::Result<'v, Self> {
        Ok(Self(Cow::Borrowed(field.value)))
    }
}

impl UserId<'_> {
    pub fn clone(&self) -> Self {
        Self(self.0.clone())
    }
    pub fn to_owned(&self) -> UserId<'static> {
        UserId(Cow::Owned(self.0.clone().into_owned()))
    }
}

#[rocket::async_trait]
pub trait UserDb: 'static {
    type UserInfo: Sync + Send;
    type DbError: 'static;
    async fn get_user(
        &self,
        id: &UserId<'_>,
    ) -> Result<Option<(AuthHash, Self::UserInfo)>, Self::DbError>;
    async fn create_user(
        &self,
        id: UserId<'_>,
        auth: AuthHash,
        info: Self::UserInfo,
    ) -> Result<bool, Self::DbError>;
    async fn update_user(&self, id: UserId<'_>, auth: AuthHash) -> Result<bool, Self::DbError>;
    fn auth_fairing() -> AuthFairing<Self> {
        AuthFairing::fairing()
    }
}

#[derive(Debug)]
pub struct AuthFairing<Db: UserDb + ?Sized> {
    _db: PhantomData<fn() -> Db>,
}

/// Safety: Send and Sync aren't implemented for *const Db, but I don't actually have a *const Db
//unsafe impl<Db: UserDb> Send for AuthFairing<Db> {}
//unsafe impl<Db: UserDb> Sync for AuthFairing<Db> {}

#[rocket::async_trait]
impl<Db: UserDb + 'static> Fairing for AuthFairing<Db> {
    fn info(&self) -> Info {
        Info {
            name: "Rocket-Auth",
            kind: Kind::Ignite | Kind::Liftoff,
        }
    }

    async fn on_ignite(&self, rocket: rocket::Rocket<rocket::Build>) -> rocket::fairing::Result {
        let f: AuthConfig = rocket
            .figment()
            .extract_inner("rocket_auth")
            .unwrap_or_default();
        let logged_in = Arc::new(flurry::HashMap::new());
        rocket::fairing::Result::Ok(rocket.manage(AuthState::<Db> {
            logged_in,
            authentication_timeout: chrono::Duration::hours(f.timeout as i64),
            authentication_renew: chrono::Duration::hours(f.timeout as i64) * 3 / 4,
        }))
    }

    async fn on_liftoff(&self, rocket: &Rocket<Orbit>) {
        let state = rocket.state::<AuthState<Db>>().unwrap();
        let handle = Arc::clone(&state.logged_in);
        let shutdown = rocket.shutdown();
        let cleanup_time = state.authentication_timeout / 2;
        let timeout = state.authentication_timeout;
        rocket::tokio::spawn(async move {
            use rocket::tokio::{select, time::sleep};
            let cleanup_time = cleanup_time.to_std().unwrap_or(std::time::Duration::MAX);
            let mut shutdown = shutdown;
            loop {
                select! {
                    biased;
                    _ = &mut shutdown => { break },
                    _ = sleep(cleanup_time) => { },
                }
                let now = Utc::now();
                let guard = handle.guard();
                handle.retain(
                    |k, _v| {
                        if let Some((date, _)) = k.split_once('&') {
                            if let Ok(datetime) = DateTime::<Utc>::from_str(date) {
                                if now - datetime < timeout {
                                    return true;
                                }
                            }
                        }
                        false
                    },
                    &guard,
                );
            }
        });
    }
}

impl<Db: UserDb + ?Sized + 'static> AuthFairing<Db> {
    pub fn fairing() -> Self {
        Self { _db: PhantomData }
    }
}

#[derive(Debug, Deserialize)]
struct AuthConfig {
    timeout: u32,
}

impl Default for AuthConfig {
    fn default() -> Self {
        Self { timeout: 4 }
    }
}

struct AuthState<Db: UserDb> {
    logged_in: Arc<flurry::HashMap<String, (UserId<'static>, Db::UserInfo)>>,
    authentication_timeout: chrono::Duration,
    authentication_renew: chrono::Duration,
}

pub struct AuthCtx<'r, Db: UserDb> {
    db: Db,
    cookies: &'r CookieJar<'r>,
    cache: &'r AuthState<Db>,
}

#[rocket::async_trait]
impl<'r, 'a, Db: UserDb + FromRequest<'r> + 'static> FromRequest<'r> for AuthCtx<'r, Db> {
    type Error = Db::Error;
    async fn from_request(r: &'r Request<'_>) -> Outcome<Self, Self::Error> {
        Db::from_request(r).await.map(|db| AuthCtx {
            db,
            cookies: r.cookies(),
            cache: r.rocket().state().unwrap(),
        })
    }
}

impl<Db: UserDb + 'static> Sentinel for AuthCtx<'_, Db> {
    fn abort(rocket: &rocket::Rocket<rocket::Ignite>) -> bool {
        if rocket.state::<AuthState<Db>>().is_none() {
            log::error!("Cannot use AuthCtx without attaching `AuthFairing`");
            true
        } else {
            false
        }
    }
}

impl<'r, Db: UserDb> AuthCtx<'r, Db> {
    /// Attempt to log in to an existing account.
    ///
    /// Returns `Err` if the underlying database encounters an error, `Ok(None)` if the supplied
    /// credentials are not valid, and `Ok(Some)` if the user was successfully logged in.
    pub async fn login(
        &'r self,
        id: UserId<'_>,
        auth: impl Into<UserAuth<'_>>,
    ) -> Result<Option<User<'r, Db>>, Db::DbError> {
        Ok(if let Some((hash, info)) = self.db.get_user(&id).await? {
            if hash.verify(auth.into()) {
                let cookie = Self::create_cookie(&id);
                let guard = self.cache.logged_in.guard();
                self.cache.logged_in.insert(
                    cookie.value().to_owned(),
                    (id.to_owned(), info),
                    &guard,
                );
                let user = User::from_map(self.cache, cookie.value());
                self.cookies.add_private(cookie);
                user
            } else {
                None
            }
        } else {
            None
        })
    }

    /// Creates a new user, and logs them in.
    ///
    /// This should never return `Ok(None)`, but it is technically possible.
    pub async fn create_user(
        &self,
        id: UserId<'_>,
        auth: impl Into<UserAuth<'_>>,
        info: Db::UserInfo,
    ) -> Result<Option<User<'r, Db>>, Db::DbError> {
        let cookie = Self::create_cookie(&id);
        if self
            .db
            .create_user(id.clone(), AuthHash::hash(auth.into()), info)
            .await?
        {
            if let Some((_, info)) = self.db.get_user(&id).await? {
                let guard = self.cache.logged_in.guard();
                self.cache.logged_in.insert(
                    cookie.value().to_owned(),
                    (id.to_owned(), info),
                    &guard,
                );
                let user = User::from_map(self.cache, cookie.value());
                self.cookies.add_private(cookie);
                return Ok(user);
            }
        }
        Ok(None)
    }

    //pub async fn update_userinfo(
    //&self,
    //user: &User<'r, Db>,
    //updated: Db::UserInfo,
    //) -> Result<(), Db::DbError> {
    //let (auth, _info) = self.db.get_user(user.id.clone()).await?;
    //self.db.update_user(user.id.clone(), auth, updated).await
    //}

    pub async fn update_userauth(
        &self,
        user: User<'r, Db>,
        current: impl Into<UserAuth<'_>>,
        new: impl Into<UserAuth<'_>>,
    ) -> Result<AuthUpdate<'r, Db>, Db::DbError> {
        if let Some((auth, _info)) = self.db.get_user(&user.id).await? {
            if auth.verify(current.into()) {
                if self
                    .db
                    .update_user(user.id.clone(), AuthHash::hash(new.into()))
                    .await?
                {
                    return Ok(AuthUpdate::Ok(user));
                }
            }
        }
        Ok(AuthUpdate::Failed(user))
    }

    fn create_cookie(id: &UserId) -> Cookie<'static> {
        // the random number makes it harder to guess the plaintext version of a token. However,
        // this shouldn't matter, since private cookies should already be secure. It also protects
        // against a user logging in twice at the same time, since the two connections will have
        // different tokens.
        Cookie::build(
            TOKEN_COOKIE,
            format!(
                "{}&{:X}&{}",
                Utc::now(),
                rand::thread_rng().gen::<u8>(),
                id.0
            ),
        )
        .finish()
    }

    /// Logs out any logged in user. Any requests that are already in flight will be completed, but
    /// any new requests that attempt to use the same token will not be accepted.
    pub fn logout(&self) {
        if let Some(token) = self.cookies.get(TOKEN_COOKIE) {
            self.cache
                .logged_in
                .remove(token.value(), &self.cache.logged_in.guard());
            self.cookies.remove_private(Cookie::named(TOKEN_COOKIE));
        }
    }
}

pub enum AuthUpdate<'r, Db: UserDb> {
    Ok(User<'r, Db>),
    Failed(User<'r, Db>),
}

/// Note: This struct implements Debug, but doesn't actually print the password or token when
/// printed. This struct also doesn't implement clone to prevent keeping a copy of the password.
/// This doesn't prevent the user from saving a copy before the UserAuth is constructed, but to
/// help avoid this, UserAuth implements the ability to be directly parsed or deserialized
/// from the request itself.
///
/// However, since there is no good way to identify whether a value is a password or OAuth token
/// (since an OAuth token is technically a valid password), there are helper structs (`Password`,
/// `GoogleOAuth`, etc) which implement `FromFormField` and `Deserialize`. All methods that expect
/// a `UserAuth` also accept any of these helper structs.
pub enum UserAuth<'a> {
    Password(Password<'a>),
    GoogleOAuth(GoogleOAuth<'a>),
}
impl<'a> Debug for UserAuth<'a> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Password(_) => write!(f, "UserAuth::Password"),
            Self::GoogleOAuth(_) => write!(f, "UserAuth::GoogleOAuth"),
        }
    }
}

/// Without doing something really weird (like constructing a form or json string to
/// deserialize a Password from), it shouldn't be possible to construct a Password. This makes it
/// harder to get a string from the user (and potentially do something insecure) before passing it
/// to this library. The much easier option is to take advantage of the `Deserialize` and
/// `FromFormField` implementations, which directly parse the password from Rocket.
///
/// Password intentially doesn't implement Debug, Display, Serialize, or any other inspection
/// methods, so it shouldn't be possible to get a password out of this once it's in.
// Sadly, constructing a ValueField is actaully pretty easy, so
// `Password::from_value(ValueField::from_value(password))` constructs a `Password` from a `&str`.
// Ideally this should take more code (although taking advantage of json isn't much longer), but I
// don't think there is a way to avoid this.
#[derive(Deserialize)]
#[serde(transparent)]
pub struct Password<'a>(&'a str);
impl<'a> From<Password<'a>> for UserAuth<'a> {
    fn from(p: Password<'a>) -> Self {
        Self::Password(p)
    }
}
#[rocket::async_trait]
impl<'a> FromFormField<'a> for Password<'a> {
    fn from_value(field: ValueField<'a>) -> form::Result<'a, Self> {
        // TODO: investigate if this is worthwhile.
        // assert_ne!(field.name, "", "Password can't be used without a name");
        Ok(Self(field.value))
    }
}

#[derive(Deserialize)]
#[serde(transparent)]
pub struct GoogleOAuth<'a>(&'a str);
impl<'a> From<GoogleOAuth<'a>> for UserAuth<'a> {
    fn from(p: GoogleOAuth<'a>) -> Self {
        Self::GoogleOAuth(p)
    }
}
#[rocket::async_trait]
impl<'a> FromFormField<'a> for GoogleOAuth<'a> {
    fn from_value(field: ValueField<'a>) -> form::Result<'a, Self> {
        Ok(Self(field.value))
    }
}

impl<'a> UserAuth<'a> {
    pub fn password(password: &'a str) -> Self {
        Self::Password(Password(password))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum AuthHash {
    Password { salt: [u8; 32], hash: [u8; 32] },
    GoogleOAuth { _token: String },
}

impl AuthHash {
    /// Verify that the provided auth matches self
    fn verify(&self, auth: UserAuth<'_>) -> bool {
        match (self, auth) {
            (Self::Password { salt, hash }, UserAuth::Password(Password(s))) => {
                let mut sha = Sha256::default();
                sha.update(&salt);
                sha.update(s.as_bytes());
                let tmp = sha.finalize();
                hash.iter().zip(tmp.into_iter()).all(|(&b, h)| b == h)
            }
            _ => false,
        }
    }

    /// Creates a new AuthHash from the provided auth
    ///
    /// NOTE: the returned AuthHash may include some random state (salt). This means that even if
    /// two AuthHashes are constructed from the same UserAuth, they will not be equal.
    fn hash(auth: UserAuth<'_>) -> Self {
        match auth {
            UserAuth::Password(Password(s)) => {
                let mut salt = [0u8; 32];
                let mut hash = [0u8; 32];
                let mut rng = rand::thread_rng();
                for b in salt.iter_mut() {
                    *b = rng.gen();
                }
                let mut sha = Sha256::default();
                sha.update(&salt);
                sha.update(s.as_bytes());
                hash.iter_mut()
                    .zip(sha.finalize().into_iter())
                    .for_each(|(b, h)| *b = h);
                Self::Password { salt, hash }
            }
            _ => todo!(),
        }
    }

    pub(crate) fn to_bytes(&self) -> Vec<u8> {
        match self {
            Self::Password { salt, hash } => {
                let mut ret = Vec::with_capacity(1 + salt.len() + hash.len());
                ret.push(b'!');
                ret.extend_from_slice(salt);
                ret.extend_from_slice(hash);
                ret
            }
            _ => todo!(),
        }
    }

    pub(crate) fn from_bytes(bytes: &[u8]) -> Result<Self, AuthHashParseError> {
        match bytes[0] {
            b'!' => {
                if bytes.len() == 65 {
                    let mut salt = [0u8; 32];
                    salt.iter_mut()
                        .zip(bytes[1..33].iter())
                        .for_each(|(s, &b)| *s = b);
                    let mut hash = [0u8; 32];
                    hash.iter_mut()
                        .zip(bytes[33..65].iter())
                        .for_each(|(s, &b)| *s = b);
                    Ok(Self::Password { salt, hash })
                } else {
                    Err(AuthHashParseError::InvalidLength)
                }
            }
            _ => Err(AuthHashParseError::InvalidType),
        }
    }
}

#[derive(Debug, Hash, PartialEq, Eq)]
pub enum AuthHashParseError {
    InvalidType,
    InvalidLength,
}

impl Display for AuthHashParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}

pub struct User<'r, Db: UserDb> {
    _guard: flurry::Guard<'r>,
    id: &'r UserId<'static>,
    info: &'r Db::UserInfo,
}

// SAFETY: I believe this is safe, since every value protected by the guard to sent with the guard
// itself, so they cannot outlife the guard.
unsafe impl<'r, Db: UserDb> Send for User<'r, Db> {}

impl<Db: UserDb + 'static> Sentinel for User<'_, Db> {
    fn abort(rocket: &rocket::Rocket<rocket::Ignite>) -> bool {
        if rocket.state::<AuthState<Db>>().is_none() {
            log::error!("Cannot use User without attaching `AuthFairing`");
            true
        } else {
            false
        }
    }
}

impl<'r, Db: UserDb> User<'r, Db> {
    pub fn id(&self) -> &'r UserId {
        self.id
    }

    pub fn info(&self) -> &'r Db::UserInfo {
        self.info
    }

    //pub fn logout(&self) {
    //self.cookies.remove_private(Cookie::named(TOKEN_COOKIE));
    //}

    fn from_map(map: &'r AuthState<Db>, name: &str) -> Option<Self> {
        let guard = map.logged_in.guard();
        let (id, info) = map.logged_in.get(name, unsafe {
            // Safety: The guard is retuned with the this lifetime, so we should be able to
            // safely borrow it for the same lifetime here.
            &*(&guard as *const Guard) as &'r Guard
        })?;
        Some(Self {
            _guard: guard,
            id,
            info,
        })
    }
}

macro_rules! try_option {
    ($e:expr) => {
        match $e {
            Some(e) => e,
            None => return Outcome::Forward(()),
        }
    };
}

use rocket::outcome::try_outcome;

#[rocket::async_trait]
impl<'r, Db: UserDb + FromRequest<'r> + Send + Sync + 'static> FromRequest<'r> for User<'r, Db> {
    type Error = Db::Error;
    async fn from_request(r: &'r Request<'_>) -> Outcome<Self, Self::Error> {
        if let Some(cookie) = r.cookies().get_private(TOKEN_COOKIE) {
            if let Some((date, _)) = cookie.value().split_once('&') {
                let datetime = try_option!(DateTime::<Utc>::from_str(date).ok());
                let cache: &AuthState<Db> = r.rocket().state().unwrap();
                let duration = Utc::now() - datetime;
                if duration < cache.authentication_timeout {
                    let user = try_option!(User::from_map(cache, cookie.value()));
                    if duration > cache.authentication_renew {
                        let ctx: AuthCtx<Db> = try_outcome!(AuthCtx::<Db>::from_request(r).await);
                        let (_, info) =
                            try_option!(try_option!(ctx.db.get_user(user.id).await.ok()));
                        let new_cookie = AuthCtx::<Db>::create_cookie(&user.id);
                        {
                            let guard = cache.logged_in.guard();
                            cache.logged_in.insert(
                                new_cookie.value().to_string(),
                                (user.id.to_owned(), info),
                                &guard,
                            );
                        }
                        r.cookies().add_private(new_cookie);
                    }
                    return Outcome::Success(user);
                }
            }
        }
        r.cookies().remove_private(Cookie::named(TOKEN_COOKIE));
        Outcome::Forward(())
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {}
}
