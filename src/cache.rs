pub const MEASUREMENT_CACHE_FLUSH: i64 = 60; // every min
pub const TCP_CONNECTION_TIMEOUT: i64 = 60;
pub const UDP_CONNECTION_TIMEOUT: i64 = 60;

use std::{collections::{HashMap, HashSet}, mem};

pub struct MeasurementCache {
    pub last_flush: time::Tm,
}

impl MeasurementCache {
    pub fn new() -> MeasurementCache {
        MeasurementCache {
            last_flush: time::now(),
        }
    }
}