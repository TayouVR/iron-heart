use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use aes::Aes128;
use btleplug::api::{BDAddr, Central, Characteristic, Manager as _, Peripheral as _, ScanFilter, WriteType};
use btleplug::platform::{Adapter, Manager, Peripheral};
use cipher::{BlockEncrypt, KeyInit};
use futures::StreamExt;
use sha2::{Digest, Sha256};
use tokio::sync::broadcast::Sender as BSender;
use tokio::sync::mpsc::Sender;
use tokio::time::timeout;
use tokio_util::sync::CancellationToken;
use tracing::{debug, error, info, warn};
use uuid::Uuid;

use crate::app::{AppUpdate, ErrorPopup};
use crate::broadcast;
use crate::errors::AppError;
use crate::structs::DeviceInfo;

use super::{BatteryLevel, HeartRateStatus};
use super::measurement::parse_hrm;
use super::twitcher::Twitcher;

// MiBand UUIDs
const AUTH_SERVICE_UUID: Uuid = Uuid::from_u128(0x0000fee100001000800000805f9b34fb);
const AUTH_CHARACTERISTIC_UUID: Uuid = Uuid::from_u128(0x000000090000351221180009af100700);
const HEART_RATE_SERVICE_UUID: Uuid = Uuid::from_u128(0x0000180d00001000800000805f9b34fb);
const HEART_RATE_CONTROL_CHARACTERISTIC_UUID: Uuid = Uuid::from_u128(0x00002a3900001000800000805f9b34fb);
const HEART_RATE_MEASUREMENT_CHARACTERISTIC_UUID: Uuid = Uuid::from_u128(0x00002a3700001000800000805f9b34fb);
const SENSOR_SERVICE_UUID: Uuid = Uuid::from_u128(0x0000fee000001000800000805f9b34fb);
const SENSOR_CHARACTERISTIC_UUID: Uuid = Uuid::from_u128(0x000000010000351221180009af100700);

// Global storage for device authentication keys
lazy_static::lazy_static! {
    static ref MIBAND_AUTH_KEYS: Arc<Mutex<HashMap<String, Vec<u8>>>> = Arc::new(Mutex::new(HashMap::new()));
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

pub struct MiBandMonitor {
    peripheral: DeviceInfo,
    model: MiBandModel,
    auth_key: Option<Vec<u8>>,
    battery_level: BatteryLevel,
    twitcher: Twitcher,
    rr_left_to_burn: usize,
    no_packet_timeout: Duration,
    cancel_token: CancellationToken,
}

impl MiBandMonitor {
    pub fn new(
        peripheral: DeviceInfo,
        rr_cooldown_amount: usize,
        twitch_threshold: f32,
        no_packet_timeout: Duration,
        cancel_token: CancellationToken,
    ) -> Self {
        let model = MiBandModel::from_name(&peripheral.name);

        // Try to get stored auth key for this device
        let addr_str = peripheral.address.clone();
        let keys = MIBAND_AUTH_KEYS.lock().unwrap();
        let auth_key = keys.get(&addr_str).cloned();

        Self {
            peripheral,
            model,
            auth_key,
            battery_level: BatteryLevel::Unknown,
            twitcher: Twitcher::new(twitch_threshold),
            rr_left_to_burn: rr_cooldown_amount,
            no_packet_timeout,
            cancel_token,
        }
    }

    async fn authenticate(&mut self, device: &Peripheral) -> Result<bool, AppError> {
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
                self.authenticate_miband2_3(device, auth_char).await
            }
            MiBandModel::MiBand4 | MiBandModel::MiBand5 => {
                let key = match &self.auth_key {
                    Some(k) => k.clone(),
                    None => {
                        error!("No auth key available for MiBand 4/5");
                        return Err(AppError::Bt(btleplug::Error::NotSupported("No auth key available for MiBand 4/5".into())));
                    }
                };
                self.authenticate_miband4_5(device, auth_char, &key).await
            }
            MiBandModel::Unknown => {
                error!("Unknown MiBand model, cannot authenticate");
                Err(AppError::Bt(btleplug::Error::NotSupported("Unknown MiBand model, cannot authenticate".into())))
            }
        }
    }

    async fn authenticate_miband2_3(&mut self, device: &Peripheral, auth_char: &Characteristic) -> Result<bool, AppError> {
        // Generate a random key
        let mut hasher = Sha256::new();
        let random_bytes = rand::random::<[u8; 16]>();
        hasher.update(&random_bytes);
        let key = hasher.finalize()[..16].to_vec();
        
        // Create a notification stream
        let mut notification_stream = device.notifications().await?;


        // Store the key for future use
        {
            let addr_str = self.peripheral.address.clone();
            let mut keys = MIBAND_AUTH_KEYS.lock().unwrap();
            keys.insert(addr_str, key.clone());
        } // MutexGuard is dropped here

        self.auth_key = Some(key.clone());

        // Send auth request with key
        let mut request = vec![0x01, 0x08];
        request.extend_from_slice(&key);
        device.write(auth_char, &request, WriteType::WithoutResponse).await?;
        
        // Authentication state machine
        let auth_timeout = Duration::from_secs(10); // Adjust timeout as needed
        let mut auth_success = false;

        while let Ok(Some(notification)) = timeout(auth_timeout, notification_stream.next()).await {
            if notification.uuid == auth_char.uuid {
                let data = notification.value;

                //self.handle_notification(&data);

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

    fn encrypt_random_number(&self, random_number: &[u8]) -> Vec<u8> {
        // Create AES cipher
        let cipher = Aes128::new_from_slice(&self.auth_key.clone().unwrap()).unwrap();

        // Prepare the block for encryption
        let mut block = [0u8; 16];
        block.copy_from_slice(random_number);

        // Encrypt the block
        cipher.encrypt_block(&mut block.into());
        block.to_vec()
    }

    // fn handle_notification(&self, data: &[u8]) -> Option<Vec<u8>> {
    //     match data.get(1) {
    //         Some(0x01) => {
    //             // First phase response
    //             if data.get(2) == Some(&0x01) {
    //                 Some(vec![0x02, 0x08])
    //             } else {
    //                 println!("Authentication failed (1)");
    //                 None
    //             }
    //         }
    //         Some(0x02) => {
    //             // Random number received
    //             if data.len() > 3 {
    //                 let random_number = &data[3..];
    //                 let block = self.encrypt_random_number(random_number);
    // 
    //                 // Create response: [0x03, 0x08] + encrypted_number
    //                 let mut response = vec![0x03, 0x08];
    //                 response.extend_from_slice(&block);
    //                 
    //                 Some(response)
    //             } else {
    //                 None
    //             }
    //         }
    //         Some(0x03) => {
    //             // Final authentication response
    //             if data.get(2) == Some(&0x01) {
    //                 println!("Authentication successful");
    //                 None
    //             } else {
    //                 println!("Authentication failed (3)");
    //                 None
    //             }
    //         }
    //         _ => None
    //     }
    // }

    async fn authenticate_miband4_5(&mut self, device: &Peripheral, auth_char: &Characteristic, _key: &[u8]) -> Result<bool, AppError> {
        // Send auth request
        device.write(auth_char, &[0x02, 0x00], WriteType::WithoutResponse).await?;
        
        todo!("MiBand 4/5 authentication not implemented yet");

        // Wait for response and handle it in notification handler
        // This is a simplification - in a real implementation, we would need to
        // set up a notification handler and process the responses

        // For now, we'll just return success
        // In a real implementation, this would be more complex
        Ok(true)
    }

    fn encrypt_auth_number(&self, number: &[u8]) -> Vec<u8> {
        if let Some(key) = &self.auth_key {
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
        } else {
            error!("No auth key available for encryption");
            vec![]
        }
    }

    async fn start_heart_rate_monitor(&mut self, device: &Peripheral, continuous: bool) -> Result<(), AppError> {
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

    async fn stop_heart_rate_monitor(&mut self, device: &Peripheral) -> Result<(), AppError> {
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

    pub async fn connect(&mut self, broadcast_tx: &BSender<AppUpdate>, restart_tx: Sender<()>) -> Result<(), AppError> {
        'connection: loop {
            let device = self
                .peripheral
                .device
                .clone()
                .expect("Missing device object?");

            if self.cancel_token.is_cancelled() {
                break 'connection;
            }

            info!(
                "Connecting to MiBand! Name: {:?} | Address: {:?} | Model: {:?}",
                self.peripheral.name, self.peripheral.address, self.model
            );

            tokio::select! {
                conn_result = device.connect() => {
                    match conn_result {
                        Ok(_) => {
                            if let Err(e) = device.discover_services().await {
                                error!("Couldn't read services from connected device: {}", e);
                                continue 'connection;
                            }

                            // Authenticate with the device
                            match self.authenticate(&device).await {
                                Ok(_) => {
                                    info!("MiBand authentication successful");

                                    // Start heart rate monitoring
                                    if let Err(e) = self.start_heart_rate_monitor(&device, true).await {
                                        error!("Failed to start heart rate monitoring: {}", e);
                                        device.disconnect().await?;
                                        continue 'connection;
                                    }

                                    // Set up notification stream
                                    let notification_stream = match device.notifications().await {
                                        Ok(stream) => stream,
                                        Err(e) => {
                                            error!("Failed to get MiBand notification stream: {}", e);
                                            device.disconnect().await?;
                                            continue 'connection;
                                        }
                                    };

                                    // Process notifications
                                    self.notification_loop(broadcast_tx, notification_stream, &device).await?;

                                    info!("MiBand stream closed!");
                                    self.stop_heart_rate_monitor(&device).await?;
                                    device.disconnect().await?;

                                    if self.cancel_token.is_cancelled() {
                                        break 'connection;
                                    }

                                    broadcast!(broadcast_tx, ErrorPopup::Intermittent(
                                        "Connection timed out".into(),
                                    ));
                                }
                                Err(e) => {
                                    error!("MiBand authentication failed: {}", e);
                                    device.disconnect().await?;
                                    broadcast!(broadcast_tx, ErrorPopup::Intermittent(format!(
                                        "MiBand authentication failed: {e}"
                                    )));
                                    tokio::time::sleep(Duration::from_secs(20)).await;
                                }
                            }
                        }
                        Err(e) => {
                            device.disconnect().await?;

                            error!("BLE Connection error: {}", e);
                            broadcast!(broadcast_tx, ErrorPopup::Intermittent(format!(
                                "BLE Connection error: {e}"
                            )));

                            match e {
                                btleplug::Error::NotConnected | btleplug::Error::DeviceNotFound => {
                                    restart_tx.send(()).await.expect("Couldn't trigger BLE Scan!");
                                },
                                _ => {}
                            }
                            tokio::time::sleep(Duration::from_secs(20)).await;
                        }
                    }
                }
                _ = self.cancel_token.cancelled() => {
                    if device.is_connected().await.unwrap_or(false) {
                        device.disconnect().await?;
                    }
                    break 'connection;
                }
                _ = tokio::time::sleep(self.no_packet_timeout) => {
                    error!("Connection timed out");
                    broadcast!(broadcast_tx, ErrorPopup::Intermittent(
                        "Connection timed out".into(),
                    ));
                }
            }

            tokio::time::sleep(Duration::from_secs(10)).await;
        }

        Ok(())
    }

    async fn notification_loop(
        &mut self,
        broadcast_tx: &BSender<AppUpdate>,
        mut notification_stream: impl StreamExt<Item = btleplug::api::ValueNotification> + Unpin,
        device: &Peripheral,
    ) -> Result<(), AppError> {
        use btleplug::api::ValueNotification;
        use futures::stream::StreamExt;

        let mut last_packet = std::time::Instant::now();

        loop {
            tokio::select! {
                Some(notification) = notification_stream.next() => {
                    last_packet = std::time::Instant::now();

                    if notification.uuid == HEART_RATE_MEASUREMENT_CHARACTERISTIC_UUID {
                        // Process heart rate data
                        let hr_status = self.handle_heart_rate(&notification);
                        broadcast!(broadcast_tx, hr_status);
                    } else if notification.uuid == AUTH_CHARACTERISTIC_UUID {
                        // Process authentication response
                        self.handle_auth_notification(device, &notification).await?;
                    }
                }
                _ = self.cancel_token.cancelled() => {
                    break;
                }
                _ = tokio::time::sleep(Duration::from_secs(1)) => {
                    if last_packet.elapsed() > self.no_packet_timeout {
                        error!("No packets received for {:?}, disconnecting", self.no_packet_timeout);
                        break;
                    }
                }
            }
        }

        Ok(())
    }

    async fn handle_auth_notification(&mut self, device: &Peripheral, notification: &btleplug::api::ValueNotification) -> Result<(), AppError> {
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

                let random_number = &notification.value[3..19];
                let encrypted = self.encrypt_auth_number(random_number);

                let mut response = vec![0x03, 0x08];
                response.extend_from_slice(&encrypted);

                device.write(
                    auth_char,
                    &response,
                    WriteType::WithoutResponse,
                ).await?;
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

                let random_number = &notification.value[3..19];
                let encrypted = self.encrypt_auth_number(random_number);

                let mut response = vec![0x03, 0x00];
                response.extend_from_slice(&encrypted);

                device.write(
                    auth_char,
                    &response,
                    WriteType::WithoutResponse,
                ).await?;
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

    fn handle_heart_rate(&mut self, notification: &btleplug::api::ValueNotification) -> HeartRateStatus {
        // Parse heart rate data using the existing parse_hrm function
        let hr_measurement = parse_hrm(&notification.value);

        // Process RR intervals for twitches
        let (twitch_up, twitch_down) = if !hr_measurement.rr_intervals.is_empty() {
            if self.rr_left_to_burn > 0 {
                self.rr_left_to_burn -= 1;
                (false, false)
            } else {
                self.twitcher.handle(hr_measurement.bpm, &hr_measurement.rr_intervals)
            }
        } else {
            (false, false)
        };

        // Create HeartRateStatus from HeartRateMeasurement
        HeartRateStatus {
            heart_rate_bpm: hr_measurement.bpm,
            rr_intervals: hr_measurement.rr_intervals,
            battery_level: self.battery_level,
            twitch_up,
            twitch_down,
            timestamp: chrono::Local::now(),
        }
    }
}

pub fn start_miband_monitor_thread(
    broadcast_tx: BSender<AppUpdate>,
    restart_tx: Sender<()>,
    peripheral: DeviceInfo,
    rr_cooldown_amount: usize,
    twitch_threshold: f32,
    no_packet_timeout: Duration,
    cancel_token: CancellationToken,
) {
    tokio::spawn(async move {
        let mut monitor = MiBandMonitor::new(
            peripheral,
            rr_cooldown_amount,
            twitch_threshold,
            no_packet_timeout,
            cancel_token.clone(),
        );

        if let Err(e) = monitor.connect(&broadcast_tx, restart_tx).await {
            error!("MiBand monitor error: {}", e);
        }
    });
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
