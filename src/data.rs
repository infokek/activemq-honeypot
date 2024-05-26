use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
pub struct AttackData {
    pub timestamp: String,
    pub source_addr: String,
    pub xml_payload: String,
    pub rce_command: Option<String>,
}
