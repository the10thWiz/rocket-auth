//
// serde.rs
// Copyright (C) 2022 matthew <matthew@WINDOWS-05HIC4F>
// Distributed under terms of the MIT license.
//

use serde::ser::{Serialize, Serializer, SerializeStruct};

use crate::AuthHash;

impl Serialize for AuthHash {
    fn serialize<S>(&self, s: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match self {
            Self::Password { salt, hash } => {
                let mut s = s.serialize_struct("AuthHash", 2)?;
                s.serialize_field("s", salt)?;
                s.serialize_field("h", hash)?;
                s.end()
            }
            _ => todo!(),
        }
    }
}

// TODO: Deserialize impl

