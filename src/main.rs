use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};

use routes::{generate_otp, register, verify};
use tower_http::cors::CorsLayer;
mod otp;
mod routes;

#[derive(Clone)]
pub struct User {
    pub secret: String,
    pub enabled: bool,
}

#[derive(Clone, Default)]
pub struct SharedState<T> {
    pub users: Arc<Mutex<HashMap<T, User>>>,
}

#[tokio::main]
async fn main() {
    env_logger::init();
    let shared_state = SharedState::default();
    let app = axum::Router::new()
        .route("/generate", axum::routing::post(generate_otp))
        .route("/register", axum::routing::post(register))
        .route("/verify", axum::routing::post(verify))
        .layer(CorsLayer::very_permissive())
        .with_state(shared_state);
    let listener = tokio::net::TcpListener::bind("0.0.0.0:8080").await.unwrap();
    axum::serve(listener, app).await.unwrap();
}
