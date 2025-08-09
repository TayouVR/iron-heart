use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use aes::Aes128;
use btleplug::api::{Characteristic, Manager as _, Peripheral, ScanFilter, ValueNotification, WriteType};
use btleplug::platform::{Manager, Peripheral as PlatformPeripheral};
use cipher::{BlockEncrypt, KeyInit};
use futures::StreamExt;
use sha2::{Digest, Sha256};
use tokio::time::timeout;
use tracing::{debug, error, info};
use uuid::Uuid;

use crate::app::{ErrorPopup};
use crate::errors::AppError;
use crate::structs::DeviceInfo;

// MiBand UUIDs
pub const AUTH_SERVICE_UUID: Uuid = 
    Uuid::from_u128(0x0000fee1_0000_1000_8000_00805f9b34fb); // 0000fee1-0000-1000-8000-00805f9b34fb
pub const AUTH_CHARACTERISTIC_UUID: Uuid = 
    Uuid::from_u128(0x00000009_0000_3512_2118_0009af100700); // 00000009-0000-3512-2118-0009af100700
pub const HEART_RATE_SERVICE_UUID: Uuid = 
    Uuid::from_u128(0x0000180d_0000_1000_8000_00805f9b34fb); // 0000180d-0000-1000-8000-00805f9b34fb
pub const HEART_RATE_CONTROL_CHARACTERISTIC_UUID: Uuid = 
    Uuid::from_u128(0x00002a39_0000_1000_8000_00805f9b34fb); // 00002a39-0000-1000-8000-00805f9b34fb
pub const HEART_RATE_MEASUREMENT_CHARACTERISTIC_UUID: Uuid = 
    Uuid::from_u128(0x00002a37_0000_1000_8000_00805f9b34fb); // 00002a37-0000-1000-8000-00805f9b34fb
pub const SENSOR_SERVICE_UUID: Uuid = 
    Uuid::from_u128(0x0000fee0_0000_1000_8000_00805f9b34fb); // 0000fee0-0000-1000-8000-00805f9b34fb
pub const SENSOR_CHARACTERISTIC_UUID: Uuid = 
    Uuid::from_u128(0x00000001_0000_3512_2118_0009af100700); // 00000001-0000-3512-2118-0009af100700

// Global storage for device authentication keys
lazy_static::lazy_static! {
    static ref MIBAND_AUTH_KEYS: Arc<Mutex<HashMap<String, Vec<u8>>>> = Arc::new(Mutex::new(HashMap::new()));
}

/// A struct that represents a MiBand device and encapsulates all MiBand-specific functionality.
pub struct MiBandDevice {
    /// The device information
    pub peripheral: DeviceInfo,
    /// The model of the MiBand
    pub model: MiBandModel,
    /// The authentication key for the device
    pub auth_key: Option<Vec<u8>>,
}

impl MiBandDevice {
    /// Create a new MiBandDevice instance
    pub fn new(peripheral: DeviceInfo) -> Self {
        let model = MiBandModel::from_name(&peripheral.name);
        
        // Try to get stored auth key for this device
        let auth_key = get_miband_key(&peripheral.address);
        
        Self {
            peripheral,
            model,
            auth_key,
        }
    }
    
    /// Check if a device is a MiBand
    pub fn is_miband(name: &str) -> bool {
        name.contains("Mi Band")
    }
    
    /// Authenticate with the MiBand device
    pub async fn authenticate(&mut self, device: &impl Peripheral) -> Result<bool, AppError> {
        info!("Starting MiBand authentication for model: {:?}", self.model);
        
        // Get the auth service
        let services = device.services();
        let auth_service = services
            .iter()
            .find(|s| s.uuid == AUTH_SERVICE_UUID)
            .ok_or_else(|| AppError::Bt(btleplug::Error::NotSupported("MiBand auth service not found".into())))?;
        
        // Get the auth characteristic
        let auth_char = auth_service
            .characteristics
            .iter()
            .find(|c| c.uuid == AUTH_CHARACTERISTIC_UUID)
            .ok_or_else(|| AppError::Bt(btleplug::Error::NotSupported("MiBand auth characteristic not found".into())))?;
        
        // Subscribe to notifications
        device.subscribe(auth_char).await?;
        
        match self.model {
            MiBandModel::MiBand2 | MiBandModel::MiBand3 => {
                // Generate a random key if none exists
                if self.auth_key.is_none() {
                    let mut hasher = Sha256::new();
                    let random_bytes = rand::random::<[u8; 16]>();
                    hasher.update(&random_bytes);
                    let key = hasher.finalize()[..16].to_vec();
                    self.auth_key = Some(key);
                }
                
                // Create a notification stream
                let mut notification_stream = device.notifications().await?;
                
                // Store the key for future use
                if let Some(key) = &self.auth_key {
                    save_miband_key(&self.peripheral.address, key);
                }
                
                // Send auth request with key
                let mut request = vec![0x01, 0x08];
                request.extend_from_slice(&self.auth_key.clone().unwrap());
                device.write(auth_char, &request, WriteType::WithoutResponse).await?;
                
                // Authentication state machine
                let auth_timeout = Duration::from_secs(10); // Adjust timeout as needed
                let mut auth_success = false;
                
                while let Ok(Some(notification)) = timeout(auth_timeout, notification_stream.next()).await {
                    if notification.uuid == auth_char.uuid {
                        let data = notification.value;
                        
                        match data.get(1) {
                            Some(0x01) => {
                                if data.get(2) == Some(&0x01) {
                                    // Send request for random number
                                    device.write(
                                        auth_char,
                                        &[0x02, 0x08],
                                        WriteType::WithoutResponse
                                    ).await?;
                                } else {
                                    return Err(AppError::AuthenticationError("First phase failed".into()));
                                }
                            }
                            Some(0x02) => {
                                if data.len() > 3 {
                                    // Got random number, encrypt and send response
                                    let random_number = &data[3..];
                                    let encrypted = self.encrypt_random_number(random_number);
                                    
                                    let mut response = vec![0x03, 0x08];
                                    response.extend_from_slice(&encrypted);
                                    
                                    device.write(
                                        auth_char,
                                        &response,
                                        WriteType::WithoutResponse
                                    ).await?;
                                }
                            }
                            Some(0x03) => {
                                if data.get(2) == Some(&0x01) {
                                    auth_success = true;
                                    break;
                                } else {
                                    return Err(AppError::AuthenticationError("Final phase failed".into()));
                                }
                            }
                            _ => {}
                        }
                    }
                }
                
                // Clean up notifications
                device.unsubscribe(auth_char).await?;
                
                if auth_success {
                    Ok(true)
                } else {
                    Err(AppError::AuthenticationError("Authentication timed out".into()))
                }
            }
            MiBandModel::MiBand4 | MiBandModel::MiBand5 => {
                if self.auth_key.is_none() {
                    error!("No auth key available for MiBand 4/5");
                    return Err(AppError::Bt(btleplug::Error::NotSupported("No auth key available for MiBand 4/5".into())));
                }
                
                // Send auth request
                device.write(auth_char, &[0x02, 0x00], WriteType::WithoutResponse).await?;
                
                // This is a placeholder - MiBand 4/5 authentication is not fully implemented
                // In a real implementation, we would need to set up a notification handler and process the responses
                
                // For now, we'll just return success
                Ok(true)
            }
            MiBandModel::Unknown => {
                error!("Unknown MiBand model, cannot authenticate");
                Err(AppError::Bt(btleplug::Error::NotSupported("Unknown MiBand model, cannot authenticate".into())))
            }
        }
    }
    
    /// Encrypt a random number using the auth key
    fn encrypt_random_number(&self, random_number: &[u8]) -> Vec<u8> {
        // Create AES cipher
        let cipher = Aes128::new_from_slice(&self.auth_key.clone().unwrap()).unwrap();
        
        // Prepare the block for encryption
        let mut block = [0u8; 16];
        block.copy_from_slice(random_number);
        
        // Encrypt the block
        let mut block_array = cipher::generic_array::GenericArray::from(block);
        cipher.encrypt_block(&mut block_array);
        block_array.to_vec()
    }
    
    /// Start heart rate monitoring on the MiBand device
    pub async fn start_heart_rate_monitor(&self, device: &impl Peripheral, continuous: bool) -> Result<(), AppError> {
        // Get the heart rate service
        let services = device.services();
        
        // Set up sensor
        if let Some(sensor_service) = services.iter().find(|s| s.uuid == SENSOR_SERVICE_UUID) {
            if let Some(sensor_char) = sensor_service.characteristics.iter().find(|c| c.uuid == SENSOR_CHARACTERISTIC_UUID) {
                device.write(sensor_char, &[0x01, 0x03, 0x19], WriteType::WithoutResponse).await?;
            }
        }
        
        // Set up heart rate monitoring
        if let Some(hr_service) = services.iter().find(|s| s.uuid == HEART_RATE_SERVICE_UUID) {
            // Subscribe to heart rate notifications
            if let Some(hr_notify_char) = hr_service.characteristics.iter().find(|c| c.uuid == HEART_RATE_MEASUREMENT_CHARACTERISTIC_UUID) {
                device.subscribe(hr_notify_char).await?;
            } else {
                return Err(AppError::Bt(btleplug::Error::NotSupported("Heart rate measurement characteristic not found".into())));
            }
            
            // Configure heart rate monitoring
            if let Some(hr_control_char) = hr_service.characteristics.iter().find(|c| c.uuid == HEART_RATE_CONTROL_CHARACTERISTIC_UUID) {
                if continuous {
                    device.write(hr_control_char, &[0x15, 0x01, 0x01], WriteType::WithoutResponse).await?;
                } else {
                    device.write(hr_control_char, &[0x15, 0x02, 0x01], WriteType::WithoutResponse).await?;
                }
            } else {
                return Err(AppError::Bt(btleplug::Error::NotSupported("Heart rate control characteristic not found".into())));
            }
        } else {
            return Err(AppError::Bt(btleplug::Error::NotSupported("Heart rate service not found".into())));
        }
        
        Ok(())
    }
    
    /// Stop heart rate monitoring on the MiBand device
    pub async fn stop_heart_rate_monitor(&self, device: &impl Peripheral) -> Result<(), AppError> {
        // Get the heart rate service
        let services = device.services();
        
        // Stop heart rate monitoring
        if let Some(hr_service) = services.iter().find(|s| s.uuid == HEART_RATE_SERVICE_UUID) {
            if let Some(hr_control_char) = hr_service.characteristics.iter().find(|c| c.uuid == HEART_RATE_CONTROL_CHARACTERISTIC_UUID) {
                device.write(hr_control_char, &[0x15, 0x01, 0x00], WriteType::WithoutResponse).await?;
                device.write(hr_control_char, &[0x15, 0x02, 0x00], WriteType::WithoutResponse).await?;
            }
        }
        
        Ok(())
    }
    
    /// Handle an authentication notification from the MiBand device
    pub async fn handle_auth_notification(&self, device: &impl Peripheral, notification: &ValueNotification) -> Result<(), AppError> {
        if notification.value.len() < 3 {
            return Ok(());
        }
        
        let cmd_type = notification.value[0];
        let status = notification.value[1];
        let req_type = notification.value[2];
        
        // Find the auth characteristic
        let services = device.services();
        let auth_service = services
            .iter()
            .find(|s| s.uuid == AUTH_SERVICE_UUID)
            .ok_or_else(|| AppError::Bt(btleplug::Error::NotSupported("MiBand auth service not found".into())))?;
        
        let auth_char = auth_service
            .characteristics
            .iter()
            .find(|c| c.uuid == AUTH_CHARACTERISTIC_UUID)
            .ok_or_else(|| AppError::Bt(btleplug::Error::NotSupported("MiBand auth characteristic not found".into())))?;
        
        match (cmd_type, status) {
            // MiBand 2/3 authentication
            (0x10, 0x01) => {
                if req_type == 0x01 {
                    // Request for random number
                    device.write(
                        auth_char,
                        &[0x02, 0x08],
                        WriteType::WithoutResponse,
                    ).await?;
                } else {
                    error!("Authentication failed (1)");
                }
            }
            (0x10, 0x02) => {
                // Received random number, encrypt and send back
                if notification.value.len() < 19 {
                    error!("Invalid random number length");
                    return Ok(());
                }
                
                if let Some(key) = &self.auth_key {
                    let random_number = &notification.value[3..19];
                    let encrypted = encrypt_auth_number(random_number, key);
                    
                    let mut response = vec![0x03, 0x08];
                    response.extend_from_slice(&encrypted);
                    
                    device.write(
                        auth_char,
                        &response,
                        WriteType::WithoutResponse,
                    ).await?;
                } else {
                    error!("No auth key available for encryption");
                }
            }
            (0x10, 0x03) => {
                if req_type == 0x01 {
                    info!("MiBand 2/3 authentication successful");
                } else {
                    error!("Authentication failed (3)");
                }
            }
            
            // MiBand 4/5 authentication
            (0x01, 0x01) => {
                if req_type == 0x01 {
                    device.write(
                        auth_char,
                        &[0x02, 0x08],
                        WriteType::WithoutResponse,
                    ).await?;
                } else {
                    error!("Authentication failed (1)");
                }
            }
            (0x01, 0x02) => {
                // Received random number, encrypt and send back
                if notification.value.len() < 19 {
                    error!("Invalid random number length");
                    return Ok(());
                }
                
                if let Some(key) = &self.auth_key {
                    let random_number = &notification.value[3..19];
                    let encrypted = encrypt_auth_number(random_number, key);
                    
                    let mut response = vec![0x03, 0x00];
                    response.extend_from_slice(&encrypted);
                    
                    device.write(
                        auth_char,
                        &response,
                        WriteType::WithoutResponse,
                    ).await?;
                } else {
                    error!("No auth key available for encryption");
                }
            }
            (0x01, 0x03) => {
                if req_type == 0x01 {
                    info!("MiBand 4/5 authentication successful");
                } else {
                    error!("Authentication failed (3)");
                }
            }
            
            _ => {
                debug!("Unknown auth notification: {:?}", notification.value);
            }
        }
        
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MiBandModel {
    MiBand2,
    MiBand3,
    MiBand4,
    MiBand5,
    Unknown,
}

impl MiBandModel {
    pub fn from_name(name: &str) -> Self {
        if name.contains("Mi Band 2") {
            MiBandModel::MiBand2
        } else if name.contains("Mi Band 3") {
            MiBandModel::MiBand3
        } else if name.contains("Mi Band 4") {
            MiBandModel::MiBand4
        } else if name.contains("Mi Band 5") {
            MiBandModel::MiBand5
        } else {
            MiBandModel::Unknown
        }
    }
}

// Helper function to save a key for a specific device
pub fn save_miband_key(address: &str, key: &[u8]) {
    let mut keys = MIBAND_AUTH_KEYS.lock().unwrap();
    keys.insert(address.to_string(), key.to_vec());
}

// Helper function to get a key for a specific device
pub fn get_miband_key(address: &str) -> Option<Vec<u8>> {
    let keys = MIBAND_AUTH_KEYS.lock().unwrap();
    keys.get(address).cloned()
}

// Helper function to parse a hex string into bytes
pub fn parse_hex_key(hex_string: &str) -> Option<Vec<u8>> {
    if hex_string.len() % 2 != 0 {
        return None;
    }

    let mut bytes = Vec::with_capacity(hex_string.len() / 2);

    for i in (0..hex_string.len()).step_by(2) {
        if let Ok(byte) = u8::from_str_radix(&hex_string[i..i+2], 16) {
            bytes.push(byte);
        } else {
            return None;
        }
    }

    Some(bytes)
}

/// Check if a device is a MiBand based on its name
pub fn is_miband(device: &DeviceInfo) -> bool {
    device.name.contains("Mi Band")
}

pub fn encrypt_auth_number(number: &[u8], key: &[u8]) -> Vec<u8> {
    // Create AES-128 cipher with ECB mode
    let cipher = Aes128::new_from_slice(key).expect("Invalid key length");

    // Ensure the number is a multiple of the block size (16 bytes)
    let mut blocks = vec![0u8; (number.len() + 15) / 16 * 16];
    blocks[..number.len()].copy_from_slice(number);

    // Convert to blocks for encryption
    let mut blocks: Vec<_> = blocks
        .chunks_exact_mut(16)
        .map(|chunk| {
            let mut block = cipher::generic_array::GenericArray::default();
            block.copy_from_slice(chunk);
            block
        })
        .collect();

    // Encrypt in place
    for block in &mut blocks {
        cipher.encrypt_block(block);
    }

    // Convert back to bytes
    blocks.iter().flat_map(|block| block.iter().cloned()).collect()
}
