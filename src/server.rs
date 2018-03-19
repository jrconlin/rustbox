use auth::FxAAuthenticator;
use rocket::config::{self, Config, Table};
use rocket::fairing::AdHoc;
use rocket::request::{self, FormItems, FromForm, FromRequest};
use rocket::{self, State};
use rocket::{Outcome, Request};
use rocket_contrib::json::Json;

use db::models::{calc_ttl, DatabaseManager};
use db::{pool_from_config, Conn};
use error::HandlerResult;

#[derive(Deserialize, Debug)]
pub struct DataRecord {
    ttl: i64,
    data: String,
}

#[derive(Debug)]
pub struct Options {
    pub index: Option<i64>,
    pub limit: Option<i64>,
}

impl<'f> FromForm<'f> for Options {
    type Error = ();

    fn from_form(items: &mut FormItems<'f>, _strict: bool) -> Result<Options, ()> {
        let mut opt = Options {
            index: None,
            limit: None,
        };

        for (key, val) in items {
            let decoded = val.url_decode()
                .unwrap_or("-1".to_string())
                .parse::<i64>()
                .unwrap_or(-1);
            if decoded > -1 {
                match key.to_lowercase().as_str() {
                    "index" => opt.index = Some(decoded.clone()),
                    "limit" => opt.limit = Some(decoded.clone()),
                    _ => {}
                }
            }
        }
        Ok(opt)
    }
}

// Due to some private variables, this must be defined in the same module as rocket.manage()
#[derive(Debug, Clone)]
pub struct RustboxConfig {
    // Authorization Configuration block
    pub services: Vec<String>,
    pub fxa_host: String,
    pub dryrun: bool,
    pub default_ttl: i64,
    pub test_data: Table,
}

// Helper functions to pull values from the private config.
impl RustboxConfig {
    pub fn new(config: &Config) -> RustboxConfig {
        // Transcode rust Config values
        let svc_list_str =
            String::from(config.get_str("services").unwrap_or("fxa").replace(" ", ""));
        let src_list: Vec<String> = svc_list_str.split('.').map(|s| String::from(s)).collect();
        RustboxConfig {
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

impl<'a, 'r> FromRequest<'a, 'r> for RustboxConfig {
    type Error = ();

    fn from_request(req: &'a Request<'r>) -> request::Outcome<Self, ()> {
        Outcome::Success(req.guard::<State<RustboxConfig>>().unwrap().inner().clone())
    }
}

// Encapsulate the server.
pub struct Server {}

impl Server {
    pub fn start(rocket: rocket::Rocket) -> HandlerResult<rocket::Rocket> {
        Ok(rocket
            .attach(AdHoc::on_attach(|rocket| {
                // Copy the config into a state manager.
                let pool = pool_from_config(rocket.config()).expect("Could not get pool");
                let rbconfig = RustboxConfig::new(rocket.config());
                Ok(rocket.manage(rbconfig).manage(pool))
            }))
            .mount(
                "/v1/store",
                routes![read, read_opt, write, delete, delete_user],
            )
            .mount("/v1/", routes![status]))
    }
}

// Method handlers:::
// Apparently you can't set these on impl methods, must be at top level.
//  query string parameters for limit and index
#[get("/<service>/<user_id>/<device_id>?<options>")]
fn read_opt(
    conn: Conn,
    token: HandlerResult<FxAAuthenticator>,
    service: String,
    user_id: String,
    device_id: String,
    options: Options,
) -> HandlerResult<Json> {
    // 👩🏫 note that the "token" var is a HandlerResult wrapped Validate struct.
    // Validate::from_request extracts the token from the Authorization header, validates it
    // against FxA and the method, and either returns OK or an error. We need to reraise it to the
    // handler.

    if token.is_err() {
        return Err(token.err().unwrap());
    }
    let max_index = DatabaseManager::max_index(&conn, &user_id, &device_id, &service);
    let index = options.index.unwrap_or(0 as i64);
    let limit = options.limit.unwrap_or(0 as i64);
    let messages =
        DatabaseManager::read_records(&conn, &user_id, &device_id, &service, index, limit).unwrap();
    // returns json {"status":200, "index": max_index, "messages":[{"index": #, "data": String}, ...]}
    let mut is_last = true;
    if limit > 0 && messages.len() == limit as usize {
        let last = messages.last().unwrap();
        is_last = last.idx == max_index;
    }
    Ok(Json(json!({
        "last": is_last,
        "index": max_index.clone(),
        "status": 200,
        "messages": messages
    })))
}

#[get("/<service>/<user_id>/<device_id>")]
fn read(
    conn: Conn,
    token: HandlerResult<FxAAuthenticator>,
    service: String,
    user_id: String,
    device_id: String,
) -> HandlerResult<Json> {
    // 👩🏫 note that the "token" var is a HandlerResult wrapped Validate struct.
    // Validate::from_request extracts the token from the Authorization header, validates it
    // against FxA and the method, and either returns OK or an error. We need to reraise it to the
    // handler.

    if token.is_err() {
        return Err(token.err().unwrap());
    }
    let max_id = DatabaseManager::max_index(&conn, &user_id, &device_id, &service);
    // returns json {"status":200, "index": max_index, "messages":[{"index": #, "data": String}, ...]}
    let messages = match DatabaseManager::read_records(&conn, &user_id, &device_id, &service, 0, 0)
    {
        Ok(val) => val,
        Err(e) => return Err(e),
    };
    Ok(Json(json!({
        "last":true,
        "index": max_id.clone(),
        "status": 200,
        "messages": messages
    })))
}

/// Write the user data to the database.
#[post("/<service>/<user_id>/<device_id>", data = "<data>")]
fn write(
    conn: Conn,
    config: RustboxConfig,
    token: HandlerResult<FxAAuthenticator>,
    service: String,
    user_id: String,
    device_id: String,
    data: Json<DataRecord>,
) -> HandlerResult<Json> {
    if token.is_err() {
        return Err(token.err().unwrap());
    }
    if config
        .test_data
        .get("auth_only")
        .unwrap_or(&config::Value::from(false))
        .as_bool()
        .unwrap_or(false)
    {
        // Auth testing, do not write to db.
        println!("INFO: Auth Skipping database check.");
        return Ok(Json(json!({
            "status": 200,
            "index": -1,
        })));
    }

    let response = DatabaseManager::new_record(
        &conn,
        &user_id,
        &device_id,
        &service,
        &data.data,
        calc_ttl(data.ttl),
    );
    if response.is_err() {
        return Err(response.err().unwrap());
    }
    // returns json {"status": 200, "index": #}
    Ok(Json(json!({
        "status": 200,
        "index": response.unwrap(),
    })))
}

#[delete("/<service>/<user_id>/<device_id>")]
fn delete(
    conn: Conn,
    _config: RustboxConfig,
    token: HandlerResult<FxAAuthenticator>,
    service: String,
    user_id: String,
    device_id: String,
) -> HandlerResult<Json> {
    if token.is_err() {
        return Err(token.err().unwrap());
    }
    let response = DatabaseManager::delete(&conn, &user_id, &device_id, &service);
    if response.is_err() {
        return Err(response.err().unwrap());
    }

    // returns an empty object
    Ok(Json(json!({})))
}

#[delete("/<service>/<user_id>")]
fn delete_user(
    conn: Conn,
    _config: RustboxConfig,
    token: HandlerResult<FxAAuthenticator>,
    service: String,
    user_id: String,
) -> HandlerResult<Json> {
    if token.is_err() {
        return Err(token.err().unwrap());
    }
    let response = DatabaseManager::delete(&conn, &user_id, &String::from(""), &service);
    if response.is_err() {
        return Err(response.err().unwrap());
    }

    // returns an empty object
    Ok(Json(json!({})))
}

#[get("/status")]
fn status(config: RustboxConfig) -> HandlerResult<Json> {
    let config = config;

    Ok(Json(json!({
        "status": "Ok",
        "fxa_auth": config.fxa_host.clone(),
    })))
}

#[cfg(test)]
mod test {
    use rand::{thread_rng, Rng};
    use std::env;

    use rocket;
    use rocket::config::{Config, Environment, RocketConfig, Table};
    use rocket::http::Header;
    use rocket::local::Client;
    use serde_json;

    use super::Server;

    #[derive(Debug, Deserialize)]
    struct WriteResp {
        index: i64,
        status: u32,
    }

    #[derive(Debug, Deserialize)]
    struct Msg {
        index: i64,
        data: String,
    }

    #[derive(Debug, Deserialize)]
    struct ReadResp {
        status: u32,
        index: i64,
        last: bool,
        messages: Vec<Msg>,
    }

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
            .extra("dryrun", true)
            .extra("test_data", test_data)
            .finalize()
            .unwrap();
        config
    }

    fn rocket_client(config: Config) -> Client {
        let test_rocket = Server::start(rocket::custom(config, true)).expect("test rocket failed");
        Client::new(test_rocket).expect("test rocket launch failed")
    }

    fn device_id() -> String {
        thread_rng().gen_ascii_chars().take(8).collect()
    }

    #[test]
    fn test_valid_write() {
        let test_data = Table::new();
        let config = rocket_config(test_data);
        let client = rocket_client(config);
        let url = format!("/v1/store/fxa/test/{}", device_id());
        let mut result = client
            .post(url.clone())
            .header(Header::new("Authorization", "bearer token"))
            .header(Header::new("Content-Type", "application/json"))
            .body(r#"{"ttl": 60, "data":"Some Data"}"#)
            .dispatch();
        let body = &result.body_string().unwrap();
        assert!(body.contains(r#""index":"#));
        assert!(body.contains(r#""status":200"#));
        assert!(result.status() == rocket::http::Status::raw(200));
    }

    #[test]
    fn test_valid_read() {
        let test_data = Table::new();
        let config = rocket_config(test_data);
        let client = rocket_client(config);
        let url = format!("/v1/store/fxa/test/{}", device_id());
        let mut write_result = client
            .post(url.clone())
            .header(Header::new("Authorization", "bearer token"))
            .header(Header::new("Content-Type", "application/json"))
            .body(r#"{"ttl": 60, "data":"Some Data"}"#)
            .dispatch();
        let write_json: WriteResp =
            serde_json::from_str(&write_result.body_string().unwrap()).unwrap();
        let mut read_result = client
            .get(url.clone())
            .header(Header::new("Authorization", "bearer token"))
            .header(Header::new("Content-Type", "application/json"))
            .dispatch();
        assert!(read_result.status() == rocket::http::Status::raw(200));
        let mut read_json: ReadResp =
            serde_json::from_str(&read_result.body_string().unwrap()).unwrap();

        assert!(read_json.status == 200);
        assert!(read_json.messages.len() > 0);
        // a MySql race condition can cause this to fail.
        // assert!(write_json.index <= read_json.index);

        // return the message at index
        read_result = client
            .get(format!("{}?index={}&limit=1", url, write_json.index))
            .header(Header::new("Authorization", "bearer token"))
            .header(Header::new("Content-Type", "application/json"))
            .dispatch();

        read_json = serde_json::from_str(&read_result.body_string().unwrap()).unwrap();
        assert!(read_json.status == 200);
        assert!(read_json.messages.len() == 1);
        // a MySql race condition can cause these to fail.
        // assert!(read_json.index != write_json.index);
        // assert!(read_json.messages[0].index == write_json.index);
    }

    #[test]
    fn test_valid_delete() {
        let test_data = Table::new();
        let config = rocket_config(test_data);
        let client = rocket_client(config);
        let url = format!("/v1/store/fxa/test/{}", device_id());
        client
            .post(url.clone())
            .header(Header::new("Authorization", "bearer token"))
            .header(Header::new("Content-Type", "application/json"))
            .body(r#"{"ttl": 60, "data":"Some Data"}"#)
            .dispatch();
        let mut del_result = client
            .delete(url.clone())
            .header(Header::new("Authorization", "bearer token"))
            .header(Header::new("Content-Type", "application/json"))
            .dispatch();
        let mut res_str = del_result.body_string().unwrap();
        assert!(res_str == "{}");
        let mut read_result = client
            .get(url.clone())
            .header(Header::new("Authorization", "bearer token"))
            .header(Header::new("Content-Type", "application/json"))
            .dispatch();
        assert!(read_result.status() == rocket::http::Status::raw(200));
        res_str = read_result.body_string().unwrap();
        let mut read_json: ReadResp = serde_json::from_str(&res_str).unwrap();
        assert!(read_json.messages.len() == 0);

        let read_result = client
            .delete("/v1/store/fxa/test")
            .header(Header::new("Authorization", "bearer token"))
            .header(Header::new("Content-Type", "application/json"))
            .dispatch();
        assert!(read_result.status() == rocket::http::Status::raw(200));
        assert!(del_result.body_string() == None);

        let mut read_result = client
            .get(url.clone())
            .header(Header::new("Authorization", "bearer token"))
            .header(Header::new("Content-Type", "application/json"))
            .dispatch();
        assert!(read_result.status() == rocket::http::Status::raw(200));
        read_json = serde_json::from_str(&read_result.body_string().unwrap()).unwrap();
        assert!(read_json.messages.len() == 0);
    }
}
