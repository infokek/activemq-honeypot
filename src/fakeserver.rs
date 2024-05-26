use log::{info, debug, error, warn};

use hex;
use regex::Regex;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use serde::Deserialize;
use serde_xml_rs::from_str;

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


/// Handle connection and make fake OpenWire response.
pub async fn handle_connection(mut socket: TcpStream) -> Result<((), Vec<u8>), Box<dyn std::error::Error>> {
    let mut buffer = vec![0u8; 1024];
    let recived_size = socket.read(&mut buffer).await?;
    let received_bytes = buffer[..recived_size].to_vec();

    let openwire_response: &[u8] = include_bytes!("../resources/openwire_response.dat");
    let openwire_version: &[u8] = "5.15.6".as_bytes();
    let openwire_response: Vec<u8> = [openwire_response, openwire_version].concat();

    socket.write_all(&openwire_response).await?;

    Ok(((), received_bytes))
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
pub async fn make_java_callback(url: String, client_addr: String) -> Result<((), Option<String>), reqwest::Error> {
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

/// Check OpenWire packet and extract payload url if exists.
pub async fn check_packet(packet: Vec<u8>, client_addr: String) -> Result<((), Option<String>), Box<dyn std::error::Error>> {
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
