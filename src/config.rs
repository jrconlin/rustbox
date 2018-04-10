use rocket::config::{Config, Table};
use rocket::{Outcome, Request, State};
use rocket::request::{self, FromRequest};

// Due to some private variables, this must be defined in the same module as rocket.manage()
#[derive(Debug, Clone)]
pub struct ServerConfig {
    // Authorization Configuration block
    pub services: Vec<String>,
    pub fxa_host: String,
    pub dryrun: bool,
    pub default_ttl: i64,
    pub test_data: Table,
}

// Helper functions to pull values from the private config.
impl ServerConfig {
    pub fn new(config: &Config) -> ServerConfig {
        // Transcode rust Config values
        let svc_list_str =
            String::from(config.get_str("services").unwrap_or("fxa").replace(" ", ""));
        let src_list: Vec<String> = svc_list_str.split('.').map(|s| String::from(s)).collect();
        ServerConfig {
            services: src_list,
            fxa_host: String::from(
                config
                    .get_str("fxa_host")
                    .unwrap_or("oauth.stage.mozaws.net"),
            ),
            dryrun: config.get_bool("dryrun").unwrap_or(false),
            default_ttl: config.get_float("default_ttl").unwrap_or(3600.0) as i64,
            test_data: config
                .get_table("test_data")
                .unwrap_or(&Table::new())
                .clone(),
        }
    }
}

impl<'a, 'r> FromRequest<'a, 'r> for ServerConfig {
    type Error = ();

    fn from_request(req: &'a Request<'r>) -> request::Outcome<Self, ()> {
        Outcome::Success(req.guard::<State<ServerConfig>>().unwrap().inner().clone())
    }
}
