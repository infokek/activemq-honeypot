use std::fs;

use std::net::SocketAddr;

use log::{info, debug, error, LevelFilter};
use simplelog::{CombinedLogger, Config, WriteLogger, TermLogger, TerminalMode, ColorChoice};

use tokio::fs::OpenOptions;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpListener;
use chrono;
use toml::Value;

use serde_json::to_string;

mod fakeserver;
use fakeserver::{handle_connection, make_java_callback, check_packet};

mod backend;
use backend::bind_http_server;

mod data;
use data::AttackData;


struct MainConfig {
    service_addr: SocketAddr,
    logfile: String,
    outfile: String,
    api_enabled: bool,
    api_addr: Option<String>,
    api_user: Option<String>,
    api_password: Option<String>
}


/// Read config from specific path. 
/// Example: Config.toml
/// ```
/// service_ip = "0.0.0.0"
/// service_port = 61616
/// log = "logs/service.log"
/// outfile = "logs/out.json"
/// api_enabled = false
/// api_ip = "0.0.0.0"
/// api_port = 9123
/// api_user = ""
/// api_password = ""
/// ```
async fn read_config(config_path: &str) -> MainConfig {
    let config: String = fs::read_to_string(config_path).expect("Error! Failed to read config file");
    let config: Value = toml::from_str(&config).expect("Error! Failed to parse config file");

    let ip: &str = config["service_ip"].as_str().expect("Error! Invalid IP address in config file");
    let port: u16 = config["service_port"].as_integer().expect("Error! Invalid port in config file") as u16;
    let service_addr: SocketAddr = format!("{}:{}", ip, port).parse().expect("Error! Invalid socket address");
    
    let logfile: String = config["logfile"].as_str().expect("Error! Invalid logfile path in config file").to_string();
    let outfile: String = config["outfile"].as_str().expect("Error! Invalid outfile path in config file").to_string();

    let api_enabled: bool  = config["api_enabled"].as_bool().expect("Error! Invalid api enabled in config file");

    let mut main_config: MainConfig = MainConfig {
        service_addr: service_addr,
        logfile: logfile,
        outfile: outfile,
        api_enabled: api_enabled,
        api_addr: None,
        api_user: None,
        api_password: None
    };
    
    if api_enabled {
        let api_ip: &str = config["api_ip"].as_str().expect("Error! Invalid IP address in config file");
        let api_port: u16 = config["api_port"].as_integer().expect("Error! Invalid port in config file") as u16;
        let api_addr: SocketAddr = format!("{}:{}", api_ip, api_port).parse().expect("Error! Invalid api address");
        main_config.api_addr = Some(api_addr.to_string());
        main_config.api_user = Some(config["api_user"].as_str().expect("Error! Invalid api user in config file").to_string());
        main_config.api_password = Some(config["api_password"].as_str().expect("Error! Invalid api password in config file").to_string());        
    }

    return main_config;
}


/// Initialize logging for specific logfile.
/// log to terminal and logfile.
async fn init_logger(logfile: String) {
    CombinedLogger::init(vec![
        TermLogger::new(
            LevelFilter::Info,
            Config::default(),
            TerminalMode::Mixed,
            ColorChoice::Auto,
        ),
        WriteLogger::new(
            LevelFilter::Info,
            Config::default(),
            std::fs::OpenOptions::new()
                .append(true)
                .create(true)
                .open(logfile)
                .unwrap(),
        ),
    ])
    .expect("Error! Failed to initialize logger");
}


/// Append new line data to specific file.
async fn append_string_to_file(path: &str, data: &str) -> Result<(), Box<dyn std::error::Error>> {
    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .await?;

    file.write_all(format!("{}\n", data).as_bytes()).await?;
    Ok(())
}


#[tokio::main]
async fn main() {
    let main_config: MainConfig = read_config("Service.toml").await;
    init_logger(main_config.logfile).await;

    let outfile = main_config.outfile.clone();

    if main_config.api_enabled {
        tokio::task::spawn(async move {
            let _ = bind_http_server(&main_config.api_addr.unwrap(),
             outfile, main_config.api_user.unwrap(),
              &main_config.api_password.unwrap());
        });
    }

    let listener = TcpListener::bind(&main_config.service_addr).await.expect("Error! Failed to bind TCP listener");
    info!("Listening on {}", main_config.service_addr);
    
    while let Ok((socket, addr)) = listener.accept().await {
        let client_addr: String = format!("{}:{}", addr.ip(), addr.port());
        info!("Got new connection from {}", client_addr);
        match handle_connection(socket).await {
            Ok(((), buffer)) => {
                debug!("{} - Received raw buffer: {:?}", client_addr, buffer);
                // Check OpenWire packet and try to extract url from OpenWire payload
                match check_packet(buffer, client_addr.clone()).await {
                    Ok(((), extracted_url)) => {
                        if let Some(url) = extracted_url {
                            info!("{} - Url extracted from OpenWire payload: {}, making fake java callback to get xml stager payload...", client_addr, url);
                            let mut attackdata = AttackData {
                                timestamp: chrono::offset::Local::now().to_string(),
                                source_addr: client_addr.clone(),
                                xml_payload: url.clone(), 
                                rce_command: None
                            };
                            // Make fake java http(s) request to get xml payload and extract command from xml payload
                            match make_java_callback(url, client_addr.clone()).await {
                                Ok(((), rce_command)) => {
                                    if let Some(rce_command) = rce_command {
                                        info!("{} - Extracted RCE command from xml payload: {}", client_addr, rce_command);
                                        attackdata.rce_command = Some(rce_command);
                                    }
                                }
                                Err(err) => {
                                    error!("{} - Error making java callback: {}", client_addr, err);
                                }
                            }
                            match append_string_to_file(&main_config.outfile, to_string(&attackdata).unwrap().as_str()).await {
                                Ok(()) => {
                                    info!("{} - Exploitation information succesfully saved to file: {}", client_addr, &main_config.outfile);
                                }
                                Err(err) => {
                                    error!("{} - Error appending to a file: {}", client_addr, err);
                                }
                            }
                        }
                    }
                    Err(err) => {
                        error!("Error checking packet: {}", err);
                    }
                    }
                }
            Err(err) => {
                error!("Error handling connection: {}", err);
            }
        }
    }
}
