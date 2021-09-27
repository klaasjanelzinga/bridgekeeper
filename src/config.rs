use std::env;
use std::ffi::OsString;
use std::fmt::{Display, Formatter};

pub struct Config {
    pub mongo_db: String,
    pub mongo_url: String,
    pub masked_mongo_url: String,
    pub environment: String,
}

impl Display for Config {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Config")
            .field("mongo_db", &self.mongo_db)
            .field("environment", &self.environment)
            .field("mongo_url", &self.masked_mongo_url)
            .finish()
    }
}

fn os_var_as_string(var: &str) -> Result<String, OsString> {
    env::var_os(var).unwrap().into_string()
}

pub fn create() -> Result<Config, OsString> {
    let mongo_db = os_var_as_string("MONGO_DB")?;
    let mongo_host = os_var_as_string("MONGO_HOST")?;
    let mongo_port = os_var_as_string("MONGO_PORT")?;
    let mongo_user = os_var_as_string("MONGO_USER")?;
    let mongo_pass = os_var_as_string("MONGO_PASS")?;

    let environment = os_var_as_string("ENVIRONMENT")?;
    let mongo_url = format!(
        "mongodb://{}:{}@{}:{}/{}",
        mongo_user, mongo_pass, mongo_host, mongo_port, mongo_db
    );
    let masked_mongo_url = format!(
        "mongodb://{}:******@{}:{}/{}",
        mongo_user, mongo_host, mongo_port, mongo_db
    );
    let config = Config {
        environment,
        mongo_url,
        masked_mongo_url,
        mongo_db,
    };

    log::trace!("Created config {}", config);
    Ok(config)
}
