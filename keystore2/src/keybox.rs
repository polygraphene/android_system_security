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

/// a keybox key
#[allow(non_snake_case)]
#[derive(Debug, Serialize, Deserialize)]
pub struct Key {
    PrivateKey: PrivateKey,
    CertificateChain: CertificateChain
}

impl Key {
    /// Get certificate chain in a Vec of PEM format.
    pub fn get_chain(&self) -> Vec<Vec<u8>> {
        self.CertificateChain.Certificate.iter().map(|s| s.value.as_bytes().to_vec()).collect()
    }

    /// Get private key in PEM format.
    pub fn get_private_key(&self) -> Vec<u8> {
        self.PrivateKey.value.as_bytes().to_vec()
    }
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

/// Operation mode
#[derive(Debug, Serialize, Deserialize, Clone, Copy)]
#[serde(rename_all = "snake_case")]
#[allow(missing_docs)]
pub enum Mode {
    Broken,
    NotProvisioned,
    Disable,
}

// Why serde default only accept functions?
fn default_mode() -> Mode { Mode::Broken }
fn default_key_index() -> u32 { 0 }
fn default_os_version() -> u32 { 150000 }
fn default_os_patch_level() -> u32 { 202410 }
fn default_vendor_patch_level() -> u32 { 20241005 }
fn default_boot_patch_level() -> u32 { 20241005 }

/// Attestation config from json
#[derive(Debug, Serialize, Deserialize)]
#[allow(missing_docs)]
pub struct KeyboxConfig {
    // mode broken: Only override results when TEE is broken.
    //      always: Always override results (Don't send requests to TEE)
    //      disable: Do nothing. Pass requests to TEE and return responses.
    #[serde(default = "default_mode")]
    pub mode: Mode,
    #[serde(default = "default_key_index")]
    pub key_index: u32,
    #[serde(default = "default_os_version")]
    pub os_version: u32,
    #[serde(default = "default_os_patch_level")]
    pub os_patch_level: u32,
    #[serde(default = "default_vendor_patch_level")]
    pub vendor_patch_level: u32,
    #[serde(default = "default_boot_patch_level")]
    pub boot_patch_level: u32,
}

// Default value when config file is missing.
impl Default for KeyboxConfig {
    fn default() -> Self {
        Self { mode: Mode::Broken, key_index : 0, os_version: 150000, os_patch_level: 202410, vendor_patch_level: 20241005, boot_patch_level: 20241005 }
    }
}

/// Keybox and attestation configuration.
pub struct LoadedKeybox {
    key: Option<Key>,
    config: KeyboxConfig
}

impl LoadedKeybox {
    /// Load keybox from disk
    pub fn load_keybox_from_disk() -> LoadedKeybox {
        let db_path = crate::globals::DB_PATH.read().expect("Could not get the database directory.");

        let config = match LoadedKeybox::read_config(&db_path.join("keybox-config.json")) {
            Ok(s) => s,
            Err(e) => {
                info!("keystore2hook Could not read config keybox-config.json: {e}. Use default value.");
                KeyboxConfig::default()
            }
        };
        info!("keystore2hook Use config: {:?}", config);

        let key = match Self::read_keybox(&db_path.join("keybox.xml")) {
            Ok(s) => s.into_iter().nth(config.key_index as usize),
            Err(e) => {
                info!("keystore2hook Could not read keybox.xml: {}", e);
                None
            }
        };
        if key.is_none() {
            info!("Specified index was invalid or key was empty: index: {}.", config.key_index);
        }

        LoadedKeybox { key, config }
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

    fn read_keybox(keybox_path: &impl AsRef<Path>) -> Result<Vec<Key>> {
        let file = File::open(keybox_path)?;
        let file = BufReader::new(file);

        let kb : AndroidAttestation = serde_xml_rs::from_reader(file)?;
        let mut keys : Vec<Key> = kb.Keybox.into_iter().flat_map(|s| s.Key.into_iter()).collect();
        for s in keys.iter_mut() {
            s.PrivateKey.value = Self::clean_pem(&s.PrivateKey.value);
            for c in s.CertificateChain.Certificate.iter_mut() {
                c.value = Self::clean_pem(&c.value);
            }
        }
        if keys.is_empty() {
            Err(anyhow!("Keybox is empty"))
        } else {
            Ok(keys)
        }
    }

    /// Get mode
    pub fn get_mode(&self) -> Mode {
        self.config.mode
    }
    
    /// Get key if any
    pub fn get_key(&self) -> Option<&Key> {
        self.key.as_ref()
    }

    /// Get attestation config
    pub fn get_config(&self) -> &KeyboxConfig {
        &self.config
    }
}
