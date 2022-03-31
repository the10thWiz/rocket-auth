//
// templates.rs
// Copyright (C) 2022 matthew <matthew@WINDOWS-05HIC4F>
// Distributed under terms of the MIT license.
//

use std::{collections::HashMap, sync::Arc};

use rocket::tokio::sync::OnceCell;
use tera::{Error, Function, Value};

/// Tera function definition:
///
/// login_uri
/// auto_prompt = false
/// size = "large" [...]
/// theme = "outline" [...]
/// shape = "rectangular" [...]
/// logo_alignment = "left" [...]
#[derive(Debug, Clone)]
pub struct GoogleButton {
    client_id: Arc<OnceCell<String>>,
}

impl GoogleButton {
    // TODO: get client_id
    pub(crate) fn new(client_id: Arc<OnceCell<String>>) -> Self {
        Self { client_id }
    }
}

impl Function for GoogleButton {
    fn call(&self, args: &HashMap<String, Value>) -> tera::Result<Value> {
        let login_uri = args
            .get("login_uri")
            .ok_or_else(|| Error::msg("login_uri is required"))?
            .as_str()
            .ok_or_else(|| Error::msg("login_uri must be a string"))?;
        //let auto_prompt = args
        //.get("auto_prompt")
        //.unwrap_or(&Value::Bool(false))
        //.as_bool()
        //.ok_or_else(|| Error::msg("auto_prompt must be a bool"))?;
        //let size = Value::String(format!("large"));
        //let size = args
        //.get("size")
        //.unwrap_or(&size)
        //.as_str()
        //.ok_or_else(|| Error::msg("size must be a string"))?;
        //if !["large", ].contains(&size) {

        //}
        //let client_id = "443833525432-fk1jqejvs0hgv5mhjkhsqv9g0u6s7rnf.apps.googleusercontent.com";
        Ok(Value::String(format!(
            "<script src=\"https://accounts.google.com/gsi/client\" async defer></script>
<div id=\"g_id_onload\"
 data-client_id=\"{}\"
 data-login_uri=\"{}\"
 data-auto_prompt=\"false\">
</div>
<div class=\"g_id_signin\"
 data-type=\"standard\"
 data-size=\"large\"
 data-theme=\"outline\"
 data-text=\"sign_in_with\"
 data-shape=\"rectangular\"
 data-logo_alignment=\"left\">
</div>
",
            self.client_id.get().unwrap(), login_uri
        )))
    }

    fn is_safe(&self) -> bool {
        true
    }
}
// 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
