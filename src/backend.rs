use bcrypt::{hash, verify, DEFAULT_COST};
use std::fs::File;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use log::{info, debug, error};

/// hash password using bcrypt
fn hash_password(password: &str) -> String {
    hash(password, DEFAULT_COST).unwrap()
}

/// read file as a string
fn read_file_as_string(filename: &str) -> Result<String, Box<dyn std::error::Error>> {
    let mut file = File::open(filename)?;
    let mut contents = String::new();
    file.read_to_string(&mut contents)?;
    Ok(contents)
}

/// handle http server
fn handle_client(mut stream: TcpStream, outfile: String, valid_user: String, valid_password: &str) {
    let mut buf = [0; 1024];
    if let Ok(size) = stream.read(&mut buf) {
        // Create a String from the buffer
        let buf_string = String::from_utf8_lossy(&buf[..size]).to_string();
        debug!("Received request: {:?}", buf_string);

        // Check if the request starts with a POST method
        if buf_string.starts_with("POST") {
            // Assuming the request body contains form data in the format "username=value&password=value"
            let form_data: Vec<&str> = buf_string.split("\r\n\r\n").collect();
            if let Some(body) = form_data.get(1) {
                debug!("Form data: {:?}", body);
                let form: Vec<&str> = body.split('&').collect();
                debug!("Form split: {:?}", form);
                let username = form.get(0).unwrap_or(&"").to_string().replace("username=", "");
                let password = form.get(1).unwrap_or(&"").to_string().replace("password=", "");

                info!("{:?} - login attempt with username: {:?} and password: {:?}", stream.peer_addr(), username, password);

                if username == valid_user && verify(&password, &hash_password(valid_password)).unwrap() {
                    match read_file_as_string(&outfile) {
                        Ok(file_content) => {
                            let response = format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n{}",
                                file_content.as_bytes().len(),
                                file_content);
                            if let Err(_) = stream.write_all(response.as_bytes()) {
                                error!("Error responding to client");
                            }
                        }
                        Err(e) => {
                            error!("Error reading file: {:?}", e);
                            if let Err(_) = stream.write_all(b"HTTP/1.1 500 Internal Server Error\r\n\r\nInternal Server Error") {
                                error!("Error responding to client");
                            }
                        }
                    }
                } else {
                    if let Err(_) = stream.write_all(b"HTTP/1.1 401 Unauthorized\r\n\r\nUnauthorized") {
                        error!("Error responding to client");
                    }
                }
            }
        } else {
            // Respond with a 405 Method Not Allowed if the request method is not POST
            if let Err(_) = stream.write_all(b"HTTP/1.1 405 Method Not Allowed\r\n\r\nMethod Not Allowed") {
                error!("Error responding to client");
            }
        }
    } else {
        error!("Error reading from client");
    }
}

/// bind http server with specific parameters
pub fn bind_http_server(addr: &str, outfile: String, valid_user: String, valid_password: &str) -> Result<(), Box<dyn std::error::Error>> {
    let listener = TcpListener::bind(addr)?;
    info!("Server listening on {}", addr);

    for stream in listener.incoming() {
        let stream = stream?;
        let outfile = outfile.clone();
        let valid_user = valid_user.clone();
        let valid_password = valid_password.to_string();

        std::thread::spawn(move || {
            handle_client(stream, outfile, valid_user, &valid_password);
        });
    }

    Ok(())
}
