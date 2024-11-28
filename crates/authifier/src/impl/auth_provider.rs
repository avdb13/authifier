use std::collections::HashSet;

use base64::{
    alphabet::URL_SAFE,
    engine::{general_purpose::NO_PAD, GeneralPurpose},
    Engine,
};
use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Header, Validation};
use oauth2_types::requests::{AccessTokenRequest, AccessTokenResponse, AuthorizationCodeGrant};
use rand::Rng;
use reqwest::Url;
use sha2::{Digest, Sha256};

use crate::{
    models::{AuthProvider, AuthValidationData, ClientCredentials, CodeChallengeMethod, IdToken},
    util::gen_random_string,
    Authifier, Error, Result, Success,
};

impl AuthProvider {
    /// Save model
    pub async fn save(&self, authifier: &Authifier) -> Success {
        authifier.database.save_auth_provider(self).await
    }

    /// Create authorization URI
    pub async fn create_authorization_uri(
        &self,
        _authifier: &Authifier,
        redirect_uri: &Url,
    ) -> Result<String> {
        let client_id = self.client_credentials.client_id();

        let state = gen_random_string(32);
        let scope = self.scopes.join(",");

        let mut query_pairs = vec![
            ("client_id", client_id),
            ("redirect_uri", redirect_uri.as_ref()),
            ("response_type", "code"),
            ("scope", &scope),
            ("state", &state),
        ];

        let (code_verifier, code_challenge) = if self
            .code_challenge_methods
            .contains(&CodeChallengeMethod::S256)
        {
            let engine = GeneralPurpose::new(&URL_SAFE, NO_PAD);
            let mut arr = [0u8; 32];

            rand::thread_rng().fill(&mut arr);
            let code_verifier = engine.encode(arr);

            let digest = Sha256::digest(&code_verifier);
            let code_challenge = engine.encode(digest);

            (Some(code_verifier), Some(code_challenge))
        } else {
            (None, None)
        };

        if let Some(code_challenge) = code_challenge.as_deref() {
            query_pairs.extend([
                ("code_challenge", code_challenge),
                ("code_challenge_method", "S256"),
            ]);
        }

        let mut uri = self.authorization_endpoint.clone();
        uri.query_pairs_mut().extend_pairs(query_pairs);

        AuthValidationData {
            ap_id: self.id.clone(),
            state,
            redirect_uri: redirect_uri.to_owned(),
            code_verifier,
        };

        Ok(uri.to_string())
    }

    /// Create authorization URI
    pub async fn access_token_with_authorization_code(
        &self,
        _authifier: &Authifier,
        code: &str,
        redirect_uri: Option<&Url>,
        code_verifier: Option<&str>,
    ) -> Result<(AccessTokenResponse, Option<IdToken>)> {
        /// A request with client credentials added to it.
        #[derive(Clone, Serialize)]
        struct Request<'c, T> {
            #[serde(flatten)]
            body: T,
            client_id: &'c str,
            #[serde(skip_serializing_if = "Option::is_none")]
            client_secret: Option<&'c str>,
        }

        let client = reqwest::Client::new();

        let body = Request {
            body: AccessTokenRequest::AuthorizationCode(AuthorizationCodeGrant {
                code: code.to_owned(),
                redirect_uri: redirect_uri.cloned(),
                code_verifier: code_verifier.map(str::to_owned),
            }),
            client_id: self.client_credentials.client_id(),
            client_secret: match &self.client_credentials {
                ClientCredentials::ClientSecretBasic { client_secret, .. }
                | ClientCredentials::ClientSecretPost { client_secret, .. } => Some(client_secret),
                _ => None,
            },
        };

        let mut request = client.post(self.token_endpoint.as_ref()).form(&body);

        if let ClientCredentials::ClientSecretBasic {
            client_id,
            client_secret,
        } = &self.client_credentials
        {
            let (username, password): (String, String) = (
                form_urlencoded::byte_serialize(client_id.as_bytes()).collect(),
                form_urlencoded::byte_serialize(client_secret.as_bytes()).collect(),
            );
            request = request.basic_auth(username, Some(password));
        }

        let response = request.send().await.map_err(|_| todo!())?;

        let response: AccessTokenResponse = response.json().await.map_err(|_| todo!())?;

        Ok((response, None))
    }
}

impl AuthValidationData {
    pub fn encode(self) -> String {
        let key = EncodingKey::from_secret(todo!());

        jsonwebtoken::encode(&Header::default(), &self, &key)
            .expect("AuthValidationData should serialize")
    }

    pub fn decode(value: &str) -> Result<Self> {
        let key = DecodingKey::from_secret(todo!());

        let mut validation = Validation::new(Algorithm::HS256);

        validation.validate_exp = false;
        validation.validate_nbf = false;
        validation.required_spec_claims = HashSet::new();

        let token =
            jsonwebtoken::decode(value, &key, &validation).map_err(|_| Error::InvalidAuthState)?;

        Ok(token.claims)
    }
}
