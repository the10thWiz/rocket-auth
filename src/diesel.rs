//
// diesel.rs
// Copyright (C) 2022 matthew <matthew@WINDOWS-05HIC4F>
// Distributed under terms of the MIT license.
//

use std::error::Error;

use diesel::{
    backend::Backend,
    deserialize::{Result, FromSql},
    sql_types::Binary,
    //types::{FromSql, ToSql},
    Expression, Queryable, query_builder::QueryFragment, AppearsOnTable, serialize::ToSql,
};

use crate::{AuthHash, AuthHashParseError};

impl Error for AuthHashParseError {}

impl<DB: Backend<RawValue = [u8]>> FromSql<Binary, DB> for AuthHash {
    fn from_sql(bytes: Option<&[u8]>) -> Result<Self> {
        if let Some(bytes) = bytes {
            Self::from_bytes(bytes).map_err(|e| Box::new(e) as Box<_>)
        } else {
            Err(Box::new(AuthHashParseError::InvalidType))
        }
    }
}

impl<DB: Backend<RawValue = [u8]>> ToSql<Binary, DB> for AuthHash {
    fn to_sql<W: std::io::Write>(
        &self,
        out: &mut diesel::serialize::Output<W, DB>,
    ) -> diesel::serialize::Result {
        <&[u8] as ToSql<Binary, DB>>::to_sql(&self.to_bytes().as_slice(), out)
    }
}

impl<DB: Backend<RawValue = [u8]>> Queryable<Binary, DB> for AuthHash {
    type Row = <Vec<u8> as Queryable<Binary, DB>>::Row;
    fn build(row: Self::Row) -> Self {
        Self::from_bytes(&<Vec<u8> as Queryable<Binary, DB>>::build(row)).unwrap()
        // TODO: avoid panic
    }
}

impl Expression for AuthHash {
    type SqlType = Binary;
}

impl<DB: Backend<RawValue = [u8]>> QueryFragment<DB> for AuthHash {
    fn walk_ast(&self, mut pass: diesel::query_builder::AstPass<DB>) -> diesel::QueryResult<()> {
        pass.push_bind_param(self)
    }
}

impl<QS: ?Sized> AppearsOnTable<QS> for AuthHash {

}
