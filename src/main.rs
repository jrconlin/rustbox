#![feature(plugin, decl_macro, custom_derive, duration_extras)]
#![plugin(rocket_codegen)]

#[macro_use]
extern crate diesel;
#[macro_use]
extern crate diesel_migrations;
#[macro_use]
extern crate failure;
#[macro_use]
extern crate serde_derive;
#[macro_use]
extern crate serde_json;
#[macro_use]
extern crate slog;

extern crate mysql;
extern crate rand;
extern crate reqwest;
extern crate rocket;
extern crate rocket_contrib;
extern crate serde;
extern crate slog_async;
extern crate slog_json;
extern crate slog_stdlog;
extern crate slog_term;

mod auth;
mod config;
mod db;
mod error;
mod logging;
mod server;

fn main() {
    let rocket_serv = server::Server::start(rocket::ignite());
    rocket_serv.unwrap().launch();
}
