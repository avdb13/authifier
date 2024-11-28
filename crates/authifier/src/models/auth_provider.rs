use std::collections::HashMap;

use reqwest::Url;
use serde::{Deserialize as _, Deserializer};

#[derive(Serialize, Deserialize, Clone)]
pub struct AuthValidationData {
    ///
    pub ap_id: String,
    /// A unique identifier for the request.
    pub state: String,
    /// The URI where the end-user will be redirected after authorization.
    pub redirect_uri: Url,
    /// A string to correlate the authorization request to the token request.
    pub code_verifier: Option<String>,
}

pub type IdToken = HashMap<String, serde_json::Value>;

#[derive(Deserialize, Clone)]
pub struct AuthProvider {
    pub id: String,

    pub name: Option<String>,
    #[serde(deserialize_with = "deserialize_opt_uri")]
    pub icon: Option<Url>,
    #[serde(deserialize_with = "deserialize_uri")]
    pub issuer: Url,

    #[serde(deserialize_with = "deserialize_uri")]
    pub authorization_endpoint: Url,
    #[serde(deserialize_with = "deserialize_uri")]
    pub token_endpoint: Url,
    #[serde(deserialize_with = "deserialize_uri")]
    pub userinfo_endpoint: Url,

    pub scopes: Vec<String>,
    pub claims: HashMap<ClaimType, String>,
    pub code_challenge_methods: Vec<CodeChallengeMethod>,

    pub auto_verify_email: bool,
    pub account_linking: bool,
    pub enabled: bool,

    #[serde(flatten)]
    pub client_credentials: ClientCredentials,
}

#[derive(Serialize, Deserialize, Clone, Eq, PartialEq)]
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

impl ClientCredentials {
    pub fn client_id(&self) -> &str {
        match self {
            ClientCredentials::None { client_id }
            | ClientCredentials::ClientSecretBasic { client_id, .. }
            | ClientCredentials::ClientSecretPost { client_id, .. } => client_id,
        }
    }
}

fn deserialize_opt_uri<'de, D>(deserializer: D) -> Result<Option<Url>, D::Error>
where
    D: Deserializer<'de>,
{
    let value = Option::<String>::deserialize(deserializer)?;

    let opt = value.as_deref().map(str::parse);
    opt.transpose().map_err(serde::de::Error::custom)
}

fn deserialize_uri<'de, D>(deserializer: D) -> Result<Url, D::Error>
where
    D: Deserializer<'de>,
{
    let value = String::deserialize(deserializer)?;

    value.parse().map_err(serde::de::Error::custom)
}
