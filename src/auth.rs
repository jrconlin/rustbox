use std::collections::HashMap;
use std::time::Duration;

use reqwest;
use rocket::Outcome::{Failure, Success};
use rocket::http::Method;
use rocket::request::{self, FromRequest};
use rocket::{Request, State};

use error::{HandlerError, HandlerErrorKind, VALIDATION_FAILED};

use config::ServerConfig;

pub const FXA_IDENT_ROOT: &str = "https://identity.mozilla.com/apps/pushbox/";

#[derive(Debug)]
pub struct FxAAuthenticator {
    pub scope: Vec<String>
}

#[derive(Clone, Deserialize, Debug)]
pub struct FxAResp {
    user: String,
    client_id: String,
    scope: Vec<String>,
}

impl<'a, 'r> FromRequest<'a, 'r> for FxAAuthenticator {
    type Error = HandlerError;

    fn from_request(request: &'a Request<'r>) -> request::Outcome<Self, HandlerError> {
        let mut scopes = Vec::new();
        if let Some(auth_header) = request.headers().get_one("Authorization") {
            let method = request.method();

            // Get a copy of the rocket config from the request's managed memory.
            // There is no other way to get the rocket.config() from inside a request
            // handler.
            let config = request.guard::<State<ServerConfig>>().unwrap();
            let fxa_host = config.fxa_host.clone();
            // segments = ["v1", "store", service, uid, devid ]
            println!("### Request: {:?}", request.uri());
            let mut splitter = auth_header.splitn(2, " ");
            match splitter.next() {
                Some(schema) => if schema.to_lowercase() != "bearer".to_owned() {
                    return Failure((
                        VALIDATION_FAILED,
                        HandlerErrorKind::Unauthorized(
                            "Incorrect Authorization Header Schema".to_string(),
                        ).into(),
                    ));
                },
                None => {
                    return Failure((
                        VALIDATION_FAILED,
                        HandlerErrorKind::Unauthorized(
                            "Missing Authorization Header Schema".to_string(),
                        ).into(),
                    ))
                }
            };
            let token = match splitter.next() {
                Some(token) => token,
                None => {
                    return Failure((
                        VALIDATION_FAILED,
                        HandlerErrorKind::Unauthorized(
                            "Incorrect Authorization Header Token".to_string(),
                        ).into(),
                    ))
                }
            };
            // Get the scopes from the verify server.
            let fxa_url = format!("https://{}/v1/verify", fxa_host);
            let mut body = HashMap::new();
            body.insert("token", token);
            if config.dryrun.clone() == false {
                let client = match reqwest::Client::builder()
                    .gzip(true)
                    .timeout(Duration::from_secs(3))
                    .build()
                {
                    Ok(client) => client,
                    Err(err) => {
                        return Failure((
                            VALIDATION_FAILED,
                            HandlerErrorKind::Unauthorized(format!("Client error {:?}", err))
                                .into(),
                        ))
                    }
                };
                let mut resp: FxAResp;
                if cfg!(test) {
                    /* 
                    Sadly, there doesn't seem to be a good way to do this. We can't add a trait for mocking this because
                    the FromRequest trait doesn't allow additional methods, we can't dummy out the reqwest call, the
                    only thing we can modify and access is the config info. fortunately, the following are mostly
                    boilerplate for calling out to the FxA server.
                    */
                    let data = config
                        .test_data
                        .get("fxa_response")
                        .expect("Could not parse test fxa_response");
                    let mut fscopes: Vec<String> = Vec::new();
                    for scope in data["scope"].as_array().expect("Invalid scope array") {
                        fscopes.push(
                            scope
                                .as_str()
                                .expect("Missing valid scope for test")
                                .to_string(),
                        );
                    }
                    resp = FxAResp {
                        user: data["user"]
                            .as_str()
                            .expect("Missing user info for test")
                            .to_string(),
                        client_id: data["client_id"]
                            .as_str()
                            .expect("Missing client_id for test")
                            .to_string(),
                        scope: fscopes,
                    };

                } else {
                    // get the FxA Validiator response.
                    let mut raw_resp = match client.post(&fxa_url).json(&body).send() {
                        Ok(response) => response,
                        Err(err) => {
                            return Failure((
                                VALIDATION_FAILED,
                                HandlerErrorKind::Unauthorized(format!(
                                    "Pushbox Server Error: {:?}",
                                    err
                                )).into(),
                            ))
                        }
                    };
                    if raw_resp.status().is_success() == false {
                        // Log validation fail
                        return Failure((
                            VALIDATION_FAILED,
                            HandlerErrorKind::Unauthorized(
                                "Missing Authorization Header".to_string(),
                            ).into(),
                        ));
                    };
                    resp = match raw_resp.json() {
                        Ok(val) => val,
                        Err(e) => {
                            return Failure((
                                VALIDATION_FAILED,
                                HandlerErrorKind::Unauthorized(format!(
                                    "FxA Server error: {:?}",
                                    e
                                )).into(),
                            ))
                        }
                    };
                }
                scopes = resp.scope.clone();
            };
            return Success(FxAAuthenticator {
                scope: scopes
            });
        } else {
            // No Authorization header
            return Failure((
                VALIDATION_FAILED,
                HandlerErrorKind::Unauthorized("Missing Authorization Header".to_string()).into(),
            ));
        }
    }
}

#[cfg(test)]
mod test {
    // cargo test -- --no-capture

    use rocket;
    use rocket::config::{Config, Environment, RocketConfig, Table};
    use rocket::fairing::AdHoc;
    use rocket::http::Header;
    use rocket::local::Client;
    use rocket_contrib::json::Json;

    use error::{HandlerErrorKind, HandlerResult};
    use config::ServerConfig;
    use super::{FxAAuthenticator};

    struct StubServer {}
    impl StubServer {
    pub fn start(rocket: rocket::Rocket) -> HandlerResult<rocket::Rocket> {
        Ok(rocket
            .attach(AdHoc::on_attach(|rocket| {
                // Copy the config into a state manager.
                let rbconfig = ServerConfig::new(rocket.config());
                Ok(rocket.manage(rbconfig))
            }))
            .mount(
                "",
                routes![auth_test_read_stub, auth_test_write_stub],
            )
        )}
    }

    // The following stub function is used for testing only.
    #[get("/test/<device_id>")]
    fn auth_test_read_stub(
        token: HandlerResult<FxAAuthenticator>,
        device_id: String
    ) -> HandlerResult<Json> {
        if token.is_err() {
            return Err(token.err().unwrap().into());
        }
        let scope = token.unwrap().scope;
        Ok(Json(json!({
            "status": 200,
            "scope": scope,
        })))
    }

    // The following stub function is used for testing only.
    #[post("/test/<device_id>")]
    fn auth_test_write_stub(
        token: HandlerResult<FxAAuthenticator>,
        device_id: String
    ) -> HandlerResult<Json> {
        if token.is_err() {
            return Err(token.err().unwrap().into());
        }
        let scope = token.unwrap().scope;
        Ok(Json(json!({
            "status": 200,
            "scope": scope,
        })))
    }

    fn rocket_config(test_data: Table) -> Config {
        let rconfig = RocketConfig::read().expect("failed to read config");
        let fxa_host = rconfig
            .active()
            .get_str("fxa_host")
            .unwrap_or("oauth.stage.mozaws.net");

        let config = Config::build(Environment::Development)
            .extra("fxa_host", fxa_host)
            .extra("dryrun", false)
            .extra("test_data", test_data)
            .finalize()
            .unwrap();
        config
    }

    fn rocket_client(config: Config) -> Client {
        let test_rocket =
            StubServer::start(rocket::custom(config, true)).expect("test rocket failed");
        Client::new(test_rocket).expect("test rocket launch failed")
    }

    #[test]
    fn test_valid() {
        let mut test_data = Table::new();
        let mut fxa_response = Table::new();
        fxa_response.insert("user".to_owned(), "test".to_owned().into());
        fxa_response.insert("client_id".to_owned(), "test".to_owned().into());
        fxa_response.insert("scope".to_owned(), vec![super::FXA_IDENT_ROOT].into());
        test_data.insert("fxa_response".to_owned(), fxa_response.into());

        test_data.insert("auth_only".to_owned(), true.into());
        let client = rocket_client(rocket_config(test_data));
        let mut result = client
            .post("/test/test")
            .header(Header::new("Authorization", "bearer tokentoken"))
            .header(Header::new("Content-Type", "application/json"))
            .body(r#"{"ttl": 123, "data": "Some Data"}"#.to_string())
            .dispatch();
        assert!(result.status() == rocket::http::Status::raw(200));
        println!("### Result: {:?}", result.body_string());
    }

    #[test]
    fn test_no_auth() {
        let mut test_data = Table::new();
        let mut fxa_response = Table::new();
        fxa_response.insert("user".to_owned(), "test".to_owned().into());
        fxa_response.insert("client_id".to_owned(), "test".to_owned().into());
        fxa_response.insert(
            "scope".to_owned(),
            vec![format!("{}send/bar", super::FXA_IDENT_ROOT)].into(),
        );
        test_data.insert("fxa_response".to_owned(), fxa_response.into());
        let client = rocket_client(rocket_config(test_data));
        let result = client
            .post("/test/test")
            .header(Header::new("Content-Type", "application/json"))
            .body(r#"{"ttl": 123, "data": "Some Data"}"#)
            .dispatch();
        assert!(result.status() == rocket::http::Status::raw(401))
    }

    #[test]
    fn test_bad_auth_schema() {
        let mut test_data = Table::new();
        let mut fxa_response = Table::new();
        fxa_response.insert("user".to_owned(), "test".to_owned().into());
        fxa_response.insert("client_id".to_owned(), "test".to_owned().into());
        fxa_response.insert("scope".to_owned(), vec![super::FXA_IDENT_ROOT].into());
        test_data.insert("fxa_response".to_owned(), fxa_response.into());

        test_data.insert("auth_only".to_owned(), true.into());
        let client = rocket_client(rocket_config(test_data));
        let result = client
            .post("/test/test")
            .header(Header::new("Authorization", "invalid tokentoken"))
            .header(Header::new("Content-Type", "application/json"))
            .body(r#"{"ttl": 123, "data": "Some Data"}"#.to_string())
            .dispatch();
        assert!(result.status() == rocket::http::Status::raw(401))
    }

    #[test]
    fn test_bad_auth_no_schema() {
        let mut test_data = Table::new();
        let mut fxa_response = Table::new();
        fxa_response.insert("user".to_owned(), "test".to_owned().into());
        fxa_response.insert("client_id".to_owned(), "test".to_owned().into());
        fxa_response.insert("scope".to_owned(), vec![super::FXA_IDENT_ROOT].into());
        test_data.insert("fxa_response".to_owned(), fxa_response.into());

        test_data.insert("auth_only".to_owned(), true.into());
        let client = rocket_client(rocket_config(test_data));
        let result = client
            .post("/test/test")
            .header(Header::new("Authorization", "invalid"))
            .header(Header::new("Content-Type", "application/json"))
            .body(r#"{"ttl": 123, "data": "Some Data"}"#.to_string())
            .dispatch();
        assert!(result.status() == rocket::http::Status::raw(401))
    }

    #[test]
    fn test_bad_auth_no_token() {
        let mut test_data = Table::new();
        let mut fxa_response = Table::new();
        fxa_response.insert("user".to_owned(), "test".to_owned().into());
        fxa_response.insert("client_id".to_owned(), "test".to_owned().into());
        fxa_response.insert("scope".to_owned(), vec![super::FXA_IDENT_ROOT].into());
        test_data.insert("fxa_response".to_owned(), fxa_response.into());

        test_data.insert("auth_only".to_owned(), true.into());
        let client = rocket_client(rocket_config(test_data));
        let mut result = client
            .post("/test/test")
            .header(Header::new("Authorization", "bearer"))
            .header(Header::new("Content-Type", "application/json"))
            .body(r#"{"ttl": 123, "data": "Some Data"}"#.to_string())
            .dispatch();
        assert!(result.status() == rocket::http::Status::raw(401))
    }

    #[test]
    fn test_bad_auth_blank() {
        let mut test_data = Table::new();
        let mut fxa_response = Table::new();
        fxa_response.insert("user".to_owned(), "test".to_owned().into());
        fxa_response.insert("client_id".to_owned(), "test".to_owned().into());
        fxa_response.insert("scope".to_owned(), vec![super::FXA_IDENT_ROOT].into());
        test_data.insert("fxa_response".to_owned(), fxa_response.into());

        test_data.insert("auth_only".to_owned(), true.into());
        let client = rocket_client(rocket_config(test_data));
        let result = client
            .post("/test/test")
            .header(Header::new("Authorization", ""))
            .header(Header::new("Content-Type", "application/json"))
            .body(r#"{"ttl": 123, "data": "Some Data"}"#.to_string())
            .dispatch();
        assert!(result.status() == rocket::http::Status::raw(401))
    }

}
