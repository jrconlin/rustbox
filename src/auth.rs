use std::collections::HashMap;
use std::time::Duration;

use reqwest;
use rocket::Outcome::{Failure, Success};
use rocket::http::Method;
use rocket::request::{self, FromRequest};
use rocket::{Request, State};

use error::{HandlerError, HandlerErrorKind, VALIDATION_FAILED};
use server::RustboxConfig;

const FXA_IDENT_ROOT: &str = "https://identity.mozilla.com/apps/pushbox/";

#[derive(Debug)]
pub struct FxAAuthenticator {}

#[derive(Clone, Deserialize, Debug)]
pub struct FxAResp {
    user: String,
    client_id: String,
    scope: Vec<String>,
}

impl<'a, 'r> FromRequest<'a, 'r> for FxAAuthenticator {
    type Error = HandlerError;

    fn from_request(request: &'a Request<'r>) -> request::Outcome<Self, HandlerError> {
        if let Some(auth_header) = request.headers().get_one("Authorization") {
            let method = request.method();

            // Get a copy of the rocket config from the request's managed memory.
            // There is no other way to get the rocket.config() from inside a request
            // handler.
            let config = request.guard::<State<RustboxConfig>>().unwrap();
            let fxa_host = config.fxa_host.clone();
            // segments = ["v1", "store", service, uid, devid ]
            if request.uri().segments().count() < 4 {
                return Failure((
                    VALIDATION_FAILED,
                    HandlerErrorKind::Unauthorized(format!(
                        "Invalid URI {} segments",
                        request.uri().segments().count()
                    )).into(),
                ));
            }
            // call unwrap here because we already checked for instances.
            let service = request.uri().segments().nth(2).unwrap().to_owned();
            if config.services.contains(&service) == false {
                return Failure((VALIDATION_FAILED, HandlerErrorKind::NotFound.into()));
            }
            let device_id = request.uri().segments().nth(4).unwrap_or("").to_owned();

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
                    let mut scopes: Vec<String> = Vec::new();
                    for scope in data["scope"].as_array().expect("Invalid scope array") {
                        scopes.push(
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
                        scope: scopes,
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
                // Check if everything is allowed.
                if resp.scope.contains(&FXA_IDENT_ROOT.to_string()) {
                    return Success(FxAAuthenticator {});
                }
                // Otherwise check for explicit allowances
                match method {
                    Method::Put | Method::Post | Method::Delete => {
                        if resp.scope
                            .contains(&format!("{}send/{}", FXA_IDENT_ROOT, device_id))
                            || resp.scope.contains(&format!("{}send", FXA_IDENT_ROOT))
                        {
                            return Success(FxAAuthenticator {});
                        }
                    }
                    Method::Get => {
                        if resp.scope
                            .contains(&format!("{}recv/{}", FXA_IDENT_ROOT, device_id))
                            || resp.scope.contains(&format!("{}recv", FXA_IDENT_ROOT))
                        {
                            return Success(FxAAuthenticator {});
                        }
                    }
                    _ => {}
                }
                return Failure((
                    VALIDATION_FAILED,
                    HandlerErrorKind::Unauthorized("Access Token Unauthorized".to_string()).into(),
                ));
            }
            // Succeed for "dry runs"
            return Success(FxAAuthenticator {});
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
    use std::env;

    use rocket;
    use rocket::config::{Config, Environment, RocketConfig, Table};
    use rocket::http::Header;
    use rocket::local::Client;

    use server;

    fn rocket_config(test_data: Table) -> Config {
        let rconfig = RocketConfig::read().expect("failed to read config");
        let fxa_host = rconfig
            .active()
            .get_str("fxa_host")
            .unwrap_or("oauth.stage.mozaws.net");

        let db_url = env::var("ROCKET_DATABASE_URL")
            .unwrap_or(String::from("mysql://test:test@localhost/pushbox"));
        let config = Config::build(Environment::Development)
            .extra("fxa_host", fxa_host)
            .extra("database_url", db_url)
            .extra("dryrun", false)
            .extra("test_data", test_data)
            .finalize()
            .unwrap();
        config
    }

    fn rocket_client(config: Config) -> Client {
        let test_rocket =
            server::Server::start(rocket::custom(config, true)).expect("test rocket failed");
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
        let result = client
            .post("/v1/store/fxa/test/test")
            .header(Header::new("Authorization", "bearer tokentoken"))
            .header(Header::new("Content-Type", "application/json"))
            .body(r#"{"ttl": 123, "data": "Some Data"}"#.to_string())
            .dispatch();
        assert!(result.status() == rocket::http::Status::raw(200))
    }

    #[test]
    fn test_no_write() {
        let mut test_data = Table::new();
        let mut fxa_response = Table::new();
        fxa_response.insert("user".to_owned(), "test".to_owned().into());
        fxa_response.insert("client_id".to_owned(), "test".to_owned().into());
        fxa_response.insert(
            "scope".to_owned(),
            vec![format!("{}recv", super::FXA_IDENT_ROOT)].into(),
        );
        test_data.insert("fxa_response".to_owned(), fxa_response.into());
        let client = rocket_client(rocket_config(test_data));
        let result = client
            .post("/v1/store/fxa/test/test")
            .header(Header::new("Authorization", "bearer tokentoken"))
            .header(Header::new("Content-Type", "application/json"))
            .body(r#"{"ttl": 123, "data": "Some Data"}"#)
            .dispatch();
        assert!(result.status() == rocket::http::Status::raw(401))
    }

    #[test]
    fn test_write_device() {
        let mut test_data = Table::new();
        let mut fxa_response = Table::new();
        fxa_response.insert("user".to_owned(), "test".to_owned().into());
        fxa_response.insert("client_id".to_owned(), "test".to_owned().into());
        fxa_response.insert(
            "scope".to_owned(),
            vec![format!("{}send/test", super::FXA_IDENT_ROOT)].into(),
        );
        test_data.insert("fxa_response".to_owned(), fxa_response.into());
        let client = rocket_client(rocket_config(test_data));
        let result = client
            .post("/v1/store/fxa/test/test")
            .header(Header::new("Authorization", "bearer tokentoken"))
            .header(Header::new("Content-Type", "application/json"))
            .body(r#"{"ttl": 123, "data": "Some Data"}"#)
            .dispatch();
        assert!(result.status() == rocket::http::Status::raw(200))
    }

    #[test]
    fn test_no_write_device() {
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
            .post("/v1/store/fxa/test/boof")
            .header(Header::new("Authorization", "bearer tokentoken"))
            .header(Header::new("Content-Type", "application/json"))
            .body(r#"{"ttl": 123, "data": "Some Data"}"#)
            .dispatch();
        assert!(result.status() == rocket::http::Status::raw(401))
    }

    #[test]
    fn test_bad_path() {
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
            .post("/v1/store/fxa/invalid")
            .header(Header::new("Authorization", "bearer tokentoken"))
            .header(Header::new("Content-Type", "application/json"))
            .body(r#"{"ttl": 123, "data": "Some Data"}"#)
            .dispatch();
        assert!(result.status() == rocket::http::Status::raw(404))
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
            .post("/v1/store/fxa/test/test")
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
            .post("/v1/store/fxa/test/test")
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
            .post("/v1/store/fxa/test/test")
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
        let result = client
            .post("/v1/store/fxa/test/test")
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
            .post("/v1/store/fxa/test/test")
            .header(Header::new("Authorization", ""))
            .header(Header::new("Content-Type", "application/json"))
            .body(r#"{"ttl": 123, "data": "Some Data"}"#.to_string())
            .dispatch();
        assert!(result.status() == rocket::http::Status::raw(401))
    }

}
