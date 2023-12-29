use std::fs;

use std::net::SocketAddr;

use log::{info, debug, error, LevelFilter, warn};
use simplelog::{CombinedLogger, Config, WriteLogger, TermLogger, TerminalMode, ColorChoice};

use hex;
use regex::Regex;

use tokio::fs::OpenOptions;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use chrono;
use toml::Value;

use serde::{Deserialize, Serialize};
use serde_xml_rs::from_str;
use serde_json::to_string;


struct MainConfig {
    addr: SocketAddr,
    logfile: String,
    outfile: String,
}


#[derive(Serialize, Deserialize)]
struct AttackData {
    timestamp: String,
    source_addr: String,
    xml_payload: String,
    rce_command: Option<String>,
}


#[derive(Debug, Deserialize)]
struct Beans {
    #[serde(rename = "bean")]
    beans: Vec<Bean>,
}


#[derive(Debug, Deserialize)]
struct Bean {

    #[serde(rename = "class")]
    class: String,

    #[serde(rename = "constructor-arg")]
    constructor_arg: ConstructorArg,
}


#[derive(Debug, Deserialize)]
struct ConstructorArg {
    #[serde(rename = "list")]
    list: List,
}


#[derive(Debug, Deserialize)]
struct List {
    #[serde(rename = "value")]
    values: Vec<String>,
}


/// Read config from specific path. 
/// Example: Config.toml
/// ```
/// ip = "0.0.0.0"
/// port = 61616
/// log = "logs/service.log"
/// outfile = "logs/out.json"
/// ```
async fn read_config(config_path: &str) -> MainConfig {
    let config: String = fs::read_to_string(config_path).expect("Error! Failed to read config file");
    let config: Value = toml::from_str(&config).expect("Error! Failed to parse config file");

    let ip: &str = config["ip"].as_str().expect("Error! Invalid IP address in config file");
    let port: u16 = config["port"].as_integer().expect("Error! Invalid port in config file") as u16;

    let addr: SocketAddr = format!("{}:{}", ip, port).parse().expect("Error! Invalid socket address");
    let logfile: String = config["logfile"].as_str().expect("Error! Invalid logfile path in config file").to_string();
    let outfile: String = config["outfile"].as_str().expect("Error! Invalid outfile path in config file").to_string();

    let main_config: MainConfig = MainConfig {
        addr: addr,
        logfile: logfile,
        outfile: outfile,
    };

    return main_config;
}


/// Handle connection and make fake OpenWire response.
async fn handle_connection(mut socket: TcpStream) -> Result<((), Vec<u8>), Box<dyn std::error::Error>> {
    let mut buffer = vec![0u8; 1024];
    let recived_size = socket.read(&mut buffer).await?;
    let received_bytes = buffer[..recived_size].to_vec();

    let openwire_response: &[u8] = include_bytes!("../resources/openwire_response.dat");
    let openwire_version: &[u8] = "5.15.6".as_bytes();
    let openwire_response: Vec<u8> = [openwire_response, openwire_version].concat();

    socket.write_all(&openwire_response).await?;

    Ok(((), received_bytes))
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


/// Check OpenWire packet and extract payload url if exists.
async fn check_packet(packet: Vec<u8>, client_addr: String) -> Result<((), Option<String>), Box<dyn std::error::Error>> {
    let hex_packet: String = hex::encode(packet.clone());
    debug!("{} - Got packet {}", client_addr, hex_packet);

    // Check if hex_packet is long enough to extract the desired substring
    if hex_packet.len() >= 16 {
        // extract OpenWire ExceptionResponse (1f) from packet
        if hex_packet[8..16].to_string() == "1f000000" {
            debug!("{} - Got OpenWire ExceptionResponse header |1f 00 00 00|", client_addr);
            let packet: String = String::from_utf8_lossy(&packet).to_string();

            // extract Throwable Message (payload url)
            if packet.contains("org.springframework.context.support.ClassPathXmlApplicationContext") {
                info!("{} - Got OpenWire payload ClassPathXmlApplicationContext! (Possible Exploitation)", client_addr);
                let host_pattern: Regex = Regex::new(r"((http:\/\/|https:\/\/).*)").expect("Error! Invalid regex pattern");

                if let Some(captures) = host_pattern.captures(packet.as_str()) {
                    if let Some(payload_url) = captures.get(1) {
                        debug!("{} - Got url in OpenWire payload: {}", client_addr, payload_url.as_str());
                        return Ok(((), Some(payload_url.as_str().to_string())));
                    }
                } else {
                    warn!("{} - Url hasn't found in OpenWire payload", client_addr);
                }
            }
        }
    }
    Ok(((), None))
}


/// Parse java.lang.ProcessBuilder values from list.
/// In common cases this list contains RCE command values.
async fn parse_xml_payload(xml_content: &str) -> Result<((), Option<Vec<String>>), Box<dyn std::error::Error>> {
    let beans: Result<Beans, _> = from_str(xml_content);
    
    match beans {
        Ok(beans) => {
            for bean in beans.beans {
                if bean.class == "java.lang.ProcessBuilder" {
                    return Ok(((), Some(bean.constructor_arg.list.values)));
                }
            }
            Ok(((), None))
        }
        Err(err) => Err(Box::new(err)),
    }
}


/// Make fake java callback with next parametres:
/// ```
/// Cache-Control: no-cache
/// Pragma: no-cache
/// User-Agent: Java/
/// Host: <host>
/// Accept: text/html, image/gif, image/jpeg
/// Connection: keep-alive
/// ```
async fn make_java_callback(url: String, client_addr: String) -> Result<((), Option<String>), reqwest::Error> {
    let client = reqwest::Client::new();
    let resp = client
        .get(&url)
        .header("Cache-Control", "no-cache")
        .header("Pragma", "no-cache")
        .header("User-Agent", "Java/1.8.0_181")
        .header("Accept", "text/html, image/gif, image/jpeg")
        .header("Connection", "keep-alive")
        .send()
        .await?
        .text()
        .await?;
    debug!("{} - Got fake java callback response: {:#?}", client_addr, resp);
    match parse_xml_payload(&resp).await{
        Ok(((), rce_command)) => {
            match rce_command {
                Some(command) => {
                    debug!("{} - Extracted RCE command from xml payload: {:?}", client_addr, command);
                    Ok(((), Some(command.join(" "))))
                }
                None => {
                    warn!("{} - RCE command hasn't found in xml payload", client_addr);
                    Ok(((), None))
                }
            }
        }
        Err(err) => {
            error!("{} - Error parsing xml payload: {}", client_addr, err);
            Ok(((), None))
        }        
    }
}


// Append new line data to specific file.
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

    let listener = TcpListener::bind(&main_config.addr).await.expect("Error! Failed to bind TCP listener");

    info!("Listening on {}", main_config.addr);

    while let Ok((socket, addr)) = listener.accept().await {
        let client_addr: String = format!("{}:{}", addr.ip(), addr.port());
        info!("Got new connection from {}", client_addr);
        match handle_connection(socket).await {
            Ok(((), buffer)) => {
                debug!("{} - Received raw buffer: {:?}",client_addr, buffer);
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
