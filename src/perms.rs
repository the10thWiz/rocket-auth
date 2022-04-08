//
// perms.rs
// Copyright (C) 2022 matthew <matthew@WINDOWS-05HIC4F>
// Distributed under terms of the MIT license.
//

//use std::marker::PhantomData;

//use rocket::outcome::try_outcome;
//use rocket::request::{FromRequest, Outcome, Request};
//use rocket::sentinel::resolution::DefaultSentinel;

//use crate::{AuthState, User, UserDb, UserId};

#[macro_export]
macro_rules! permission {
    ($v:vis $name:ident = |$info:ident: &$infoty:ty| $perm:expr) => {
        $v struct $name<'r, Db: $crate::UserDb> {
            user: $crate::User<'r, Db>,
        }

        impl<'r, Db: $crate::UserDb> std::ops::Deref for $name<'r, Db> {
            type Target = $crate::User<'r, Db>;

            fn deref(&self) -> &Self::Target {
                &self.user
            }
        }

        #[rocket::async_trait]
        impl<'r, Db> ::rocket::request::FromRequest<'r> for $name<'r, Db>
        where
            Db: $crate::UserDb<UserInfo = $infoty> + ::rocket::request::FromRequest<'r> + Send + Sync + 'static
        {
            type Error = Db::Error;

            async fn from_request(r: &'r ::rocket::request::Request<'_>) -> ::rocket::request::Outcome<Self, Self::Error> {
                let user: $crate::User<'r, Db> = ::rocket::outcome::try_outcome!(r.guard().await);
                let $info = user.info();
                if $perm {
                    ::rocket::request::Outcome::Success(Self {
                        user,
                    })
                } else {
                    ::rocket::request::Outcome::Forward(())
                }
            }
        }
    };
}

#[cfg(test)]
mod tests {
    use crate::permission;
    pub struct UserInfo {
        is_admin: bool,
    }

    permission!(Admin = |info: &UserInfo| info.is_admin);
    permission!(pub Admin2 = |info: &UserInfo| info.is_admin);
}
