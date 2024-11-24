use std::{
    collections::{HashMap, HashSet},
    ops::Deref,
};

use rocket::http::hyper::Uri;
use serde::{Deserialize, Deserializer};

#[derive(Default, Clone)]
pub struct OAuth(HashSet<OAuthProvider>);

impl Deref for OAuth {
    type Target = HashSet<OAuthProvider>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<'de> Deserialize<'de> for OAuth {
    fn deserialize<D>(_deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        todo!()
    }
}

#[derive(Deserialize, Clone)]
pub struct OAuthProvider {
    pub id: String,

    pub name: Option<String>,
    #[serde(deserialize_with = "deserialize_opt_uri")]
    pub icon: Option<Uri>,
    #[serde(deserialize_with = "deserialize_uri")]
    pub issuer: Uri,

    #[serde(deserialize_with = "deserialize_uri")]
    pub authorization_endpoint: Uri,
    #[serde(deserialize_with = "deserialize_uri")]
    pub token_endpoint: Uri,
    #[serde(deserialize_with = "deserialize_uri")]
    pub userinfo_endpoint: Uri,

    pub scopes: Vec<String>,
    pub claims: HashMap<ClaimType, String>,
    pub code_challenge_methods: Vec<CodeChallengeMethod>,

    pub auto_verify_email: bool,
    pub account_linking: bool,
    pub enabled: bool,

    #[serde(flatten)]
    pub client_credentials: ClientCredentials,
}

#[derive(Serialize, Deserialize, Clone)]
pub enum CodeChallengeMethod {
    Plain,
    S256,
}

#[derive(Serialize, Deserialize, Clone, Eq, PartialEq, Hash)]
pub enum ClaimType {
    Id,
    Username,
    Picture,
    Email,
}

#[derive(Serialize, Deserialize, Clone)]
pub enum ClientCredentials {
    None {
        client_id: String,
    },
    ClientSecretBasic {
        client_id: String,
        client_secret: String,
    },
    ClientSecretPost {
        client_id: String,
        client_secret: String,
    },
}

fn deserialize_opt_uri<'de, D>(deserializer: D) -> Result<Option<Uri>, D::Error>
where
    D: Deserializer<'de>,
{
    let value = Option::<String>::deserialize(deserializer)?;

    let opt = value.as_deref().map(str::parse);
    opt.transpose().map_err(serde::de::Error::custom)
}

fn deserialize_uri<'de, D>(deserializer: D) -> Result<Uri, D::Error>
where
    D: Deserializer<'de>,
{
    let value = String::deserialize(deserializer)?;

    value.parse().map_err(serde::de::Error::custom)
}
