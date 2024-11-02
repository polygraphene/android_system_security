//! Read keybox.xml from disk.
//! 
use std::fs::File;
use std::io::BufReader;
use std::path::Path;

use serde::{Deserialize, Serialize};

use anyhow::{anyhow, Result};

use log::info;

#[allow(non_snake_case)]
#[derive(Debug, Serialize, Deserialize)]
struct AndroidAttestation {
    Keybox: Vec<Keybox>
}

#[allow(non_snake_case)]
#[derive(Debug, Serialize, Deserialize)]
struct Keybox {
    Key: Vec<Key>
}

#[allow(non_snake_case)]
#[derive(Debug, Serialize, Deserialize)]
struct Key {
    PrivateKey: PrivateKey,
    CertificateChain: CertificateChain
}

#[allow(non_snake_case)]
#[derive(Debug, Serialize, Deserialize)]
struct PrivateKey {
    #[serde(rename = "$value")]
    value: String
}

#[allow(non_snake_case)]
#[derive(Debug, Serialize, Deserialize)]
struct CertificateChain {
    Certificate: Vec<Certificate>
}

#[derive(Debug, Serialize, Deserialize)]
struct Certificate {
    #[serde(rename = "$value")]
    value: String
}

// Config from json
#[derive(Debug, Serialize, Deserialize)]
struct KeyboxConfig {
    key_index: u32,
    os_version: u32,
    os_patch_level: u32,
    vendor_patch_level: u32,
    boot_patch_level: u32,
}

// Default value when config file is missing.
impl Default for KeyboxConfig {
    fn default() -> Self {
        Self {key_index : 0, os_version: 150000, os_patch_level: 202410, vendor_patch_level: 20241005, boot_patch_level: 20241005 }
    }
}

/// Keybox and attestation configuration.
pub struct LoadedKeybox {
    keys: Vec<Key>,
    config: KeyboxConfig
}

impl LoadedKeybox {
    /// Load keybox from disk
    pub fn load_keybox_from_disk() -> Result<LoadedKeybox> {
        let db_path = crate::globals::DB_PATH.read().expect("Could not get the database directory.");
        let mut keybox_path = db_path.to_path_buf();
        keybox_path.push("keybox.xml");

        let file = File::open(keybox_path)?;
        let file = BufReader::new(file);

        let kb : AndroidAttestation = serde_xml_rs::from_reader(file)?;
        let mut keys : Vec<Key> = kb.Keybox.into_iter().flat_map(|s| s.Key.into_iter()).collect();
        if keys.is_empty() {
            return Err(anyhow!("keybox is empty"));
        }
        for s in keys.iter_mut() {
            s.PrivateKey.value = Self::clean_pem(&s.PrivateKey.value);
            for c in s.CertificateChain.Certificate.iter_mut() {
                c.value = Self::clean_pem(&c.value);
            }
        }

        let mut config_path = db_path.to_path_buf();
        config_path.push("keybox-config.json");
        let config = match LoadedKeybox::read_config(&config_path) {
            Ok(s) => s,
            Err(e) => {
                info!("Could not read config keybox-config.json: {e}. Use default value.");
                KeyboxConfig::default()
            }
        };
        info!("Use config: {:?}", config);
        if config.key_index as usize >= keys.len() {
            return Err(anyhow!("Specified index was invalid"));
        }

        Ok(LoadedKeybox { keys, config })
    }

    // pems have sometimes indent. Remove them.
    fn clean_pem(value: &str) -> String {
        value.split('\n').map(|s| s.trim()).fold(String::new(), |a, b| a.to_string() + b + "\n")
    }

    fn read_config(config_path: &impl AsRef<Path>) -> Result<KeyboxConfig> {
        let file = File::open(config_path)?;
        let file = BufReader::new(file);
        Ok(serde_json::from_reader(file)?)
    }

    /// Get certificate chain in a Vec of PEM format.
    pub fn get_chain(&self) -> Vec<Vec<u8>> {
        self.keys[self.config.key_index as usize].CertificateChain.Certificate.iter().map(|s| s.value.as_bytes().to_vec()).collect()
    }

    /// Get private key in PEM format.
    pub fn get_private_key(&self) -> Vec<u8> {
        self.keys[self.config.key_index as usize].PrivateKey.value.as_bytes().to_vec()
    }

    /// Get os version integer
    pub fn get_os_version(&self) -> u32 {
        self.config.os_version
    }

    /// Get os patch level
    pub fn get_os_patch_level(&self) -> u32 {
        self.config.os_patch_level
    }

    /// Get vendor patch level
    pub fn get_vendor_patch_level(&self) -> u32 {
        self.config.vendor_patch_level
    }

    /// Get boot patch level
    pub fn get_boot_patch_level(&self) -> u32 {
        self.config.boot_patch_level
    }
}
