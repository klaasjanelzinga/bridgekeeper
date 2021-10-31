use jsonwebtoken::{DecodingKey, EncodingKey};
use std::env;
use std::fmt::{Display, Formatter};

#[derive(Clone)]
pub struct Config<'a> {
    pub mongo_db: String,
    pub mongo_url: String,
    pub masked_mongo_url: String,
    pub environment: String,
    pub decoding_key: DecodingKey<'a>,
    pub encoding_key: EncodingKey,
}

fn os_var_as_string(var: &str) -> String {
    env::var_os(var)
        .expect(format!("Environment {} not set", var).as_ref())
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

        Config {
            environment,
            mongo_url,
            masked_mongo_url,
            mongo_db,
            decoding_key,
            encoding_key,
        }
    }
}

impl Display for Config<'_> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Config")
            .field("mongo_db", &self.mongo_db)
            .field("environment", &self.environment)
            .field("mongo_url", &self.masked_mongo_url)
            .finish()
    }
}
