use log::{info, debug, error, LevelFilter};
use actix_web::{web, App, HttpServer, HttpResponse, Responder};
use bcrypt::{verify, DEFAULT_COST};
use std::fs::File;
use std::io::Read;

use crate::data::AttackData;

#[derive(Debug)]
struct User {
    username: String,
    password_hash: String,
}

const VALID_USER: &str = "user";
const VALID_PASSWORD: &str = "password";

fn hash_password(password: &str) -> String {
    bcrypt::hash(password, DEFAULT_COST).unwrap()
}

fn read_json_file(filename: &str) -> Result<AttackData, Box<dyn std::error::Error>> {
    let mut file = File::open(filename)?;
    let mut contents = String::new();
    file.read_to_string(&mut contents)?;
    let person: AttackData = serde_json::from_str(&contents)?;
    Ok(person)
}

async fn get_data(outfile: String, form: web::Form<(String, String)>) -> impl Responder {
    if form.0 == VALID_USER && verify(&form.1, &hash_password(VALID_PASSWORD)).unwrap() {
        match read_json_file(&outfile) {
            Ok(attackdata) => info!("{:?}", attackdata),
            Err(e) => error!("Error: {}", e),
        }
        HttpResponse::Ok().body("Login successful!")
    } else {
        HttpResponse::Unauthorized().body("Invalid username or password")
    }
}

#[actix_web::main]
pub async fn bind_server(outfile: String) -> std::io::Result<()> {
    HttpServer::new(move || {
        let outfile = outfile.clone();
        App::new()
            .app_data(web::Data::new(outfile.clone()))
            .route("/", web::post().to(move |form: web::Form<(String, String)>| {
                get_data(outfile.clone(), form)
            }))
    })
    .bind("0.0.0.0:80")?
    .run()
    .await
}