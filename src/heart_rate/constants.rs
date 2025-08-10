use uuid::Uuid;

#[derive(Debug)]
pub struct MiBandService {
    pub auth: Uuid,
    pub sensor: Uuid,
}

#[derive(Debug)]
pub struct MiBandCharacteristic {
    pub auth: Uuid,
    pub sensor: Uuid,
}

#[derive(Debug)]
pub struct HeartRateCharacteristic {
    pub control: Uuid,
    pub measurement: Uuid,
}

#[derive(Debug)]
pub struct BleServices {
    pub mi_band: MiBandService,
    pub heart_rate: Uuid,
    pub battery: Uuid,
}

#[derive(Debug)]
pub struct BleCharacteristics {
    pub mi_band: MiBandCharacteristic,
    pub heart_rate: HeartRateCharacteristic,
    pub battery_level: Uuid,
}

#[derive(Debug)]
pub struct BleUuids {
    pub services: BleServices,
    pub characteristics: BleCharacteristics,
}


pub const BLE_UUIDS: BleUuids = BleUuids {
    services: BleServices {
        mi_band: MiBandService {
            auth: AUTH_SERVICE_UUID,
            sensor: SENSOR_SERVICE_UUID,
        },
        heart_rate: HEART_RATE_SERVICE_UUID,
        battery: BATTERY_SERVICE_UUID,
    },
    characteristics: BleCharacteristics {
        mi_band: MiBandCharacteristic {
            auth: AUTH_CHARACTERISTIC_UUID,
            sensor: SENSOR_CHARACTERISTIC_UUID,
        },
        heart_rate: HeartRateCharacteristic {
            control: HEART_RATE_CONTROL_CHARACTERISTIC_UUID,
            measurement: HEART_RATE_MEASUREMENT_CHARACTERISTIC_UUID,
        },
        battery_level: BATTERY_LEVEL_CHARACTERISTIC_UUID,
    },
};

// MiBand UUIDs
const AUTH_SERVICE_UUID: Uuid =
    Uuid::from_u128(0x0000fee1_0000_1000_8000_00805f9b34fb); // 0000fee1-0000-1000-8000-00805f9b34fb
const AUTH_CHARACTERISTIC_UUID: Uuid =
    Uuid::from_u128(0x00000009_0000_3512_2118_0009af100700); // 00000009-0000-3512-2118-0009af100700
const SENSOR_SERVICE_UUID: Uuid =
    Uuid::from_u128(0x0000fee0_0000_1000_8000_00805f9b34fb); // 0000fee0-0000-1000-8000-00805f9b34fb
const SENSOR_CHARACTERISTIC_UUID: Uuid =
    Uuid::from_u128(0x00000001_0000_3512_2118_0009af100700); // 00000001-0000-3512-2118-0009af100700


// heart rate
const HEART_RATE_SERVICE_UUID: Uuid =
    Uuid::from_u128(0x0000180d_0000_1000_8000_00805f9b34fb); // 0000180d-0000-1000-8000-00805f9b34fb
const HEART_RATE_CONTROL_CHARACTERISTIC_UUID: Uuid =
    Uuid::from_u128(0x00002a39_0000_1000_8000_00805f9b34fb); // 00002a39-0000-1000-8000-00805f9b34fb
const HEART_RATE_MEASUREMENT_CHARACTERISTIC_UUID: Uuid =
    Uuid::from_u128(0x00002a37_0000_1000_8000_00805f9b34fb); // 00002a37-0000-1000-8000-00805f9b34fb

// battery
const BATTERY_SERVICE_UUID: Uuid = 
    Uuid::from_u128(0x0000180f_0000_1000_8000_00805f9b34fb); // 0000180f-0000-1000-8000-00805f9b34fb
const BATTERY_LEVEL_CHARACTERISTIC_UUID: Uuid =
    Uuid::from_u128(0x00002a19_0000_1000_8000_00805f9b34fb); // 00002a19-0000-1000-8000-00805f9b34fb