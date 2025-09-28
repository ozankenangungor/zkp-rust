use tonic::{Code, Request, Response, Status, transport::Server};

pub mod zkp_auth {
    include!("./zkp_auth.rs");
}

use zkp_auth::auth_server;

fn main() {
    println!("Hi, I am the server");
}
