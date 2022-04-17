use jsonwebtoken::{DecodingKey, EncodingKey};
use std::env;
use std::fmt::{Display, Formatter};
use std::net::SocketAddr;

#[derive(Clone)]
pub struct Config<'a> {
    pub mongo_db: String,
    pub mongo_url: String,
    pub masked_mongo_url: String,
    pub environment: String,
    pub decoding_key: DecodingKey<'a>,
    pub encoding_key: EncodingKey,
    pub application_name: String,
    pub bind_to: SocketAddr,
    pub allow_origin: String,
}

fn os_var_as_string(var: &str) -> String {
    env::var_os(var)
        .unwrap_or_else(|| {
            panic!(
                "{}",
                format!("Environment {} not set. Cannot start application", var)
            )
        })
        .into_string()
        .unwrap()
}

impl Config<'_> {
    pub fn from_environment() -> Self {
        let mongo_db = os_var_as_string("MONGO_DB");
        let mongo_host = os_var_as_string("MONGO_HOST");
        let mongo_port = os_var_as_string("MONGO_PORT");
        let mongo_user = os_var_as_string("MONGO_USER");
        let mongo_pass = os_var_as_string("MONGO_PASS");
        let jwt_token_secret = os_var_as_string("JWT_TOKEN_SECRET");
        let allow_origin = os_var_as_string("ALLOW_ORIGIN");

        let environment = os_var_as_string("ENVIRONMENT");
        let mongo_url = format!(
            "mongodb://{}:{}@{}:{}/{}",
            mongo_user, mongo_pass, mongo_host, mongo_port, mongo_db
        );
        let masked_mongo_url = format!(
            "mongodb://{}:******@{}:{}/{}",
            mongo_user, mongo_host, mongo_port, mongo_db
        );

        let based = base64::encode(jwt_token_secret.as_bytes());
        let decoding_key = DecodingKey::from_base64_secret(&based).unwrap();
        let encoding_key = EncodingKey::from_base64_secret(&based).unwrap();

        let address: SocketAddr = "0.0.0.0:8000".parse().unwrap();

        Config {
            environment,
            mongo_url,
            masked_mongo_url,
            mongo_db,
            decoding_key,
            encoding_key,
            application_name: "bridgekeeper".to_string(),
            bind_to: address,
            allow_origin,
        }
    }
}

impl Display for Config<'_> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Config")
            .field("mongo_db", &self.mongo_db)
            .field("mongo_pass", &self.mongo_url)
            .field("environment", &self.environment)
            .field("mongo_url", &self.masked_mongo_url)
            .field("bind_to", &self.bind_to)
            .field("application_name", &self.application_name)
            .field("allow_origin", &self.allow_origin)
            .finish()
    }
}
