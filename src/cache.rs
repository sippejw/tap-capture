pub const MEASUREMENT_CACHE_FLUSH: i64 = 60; // every min
pub const TCP_CONNECTION_TIMEOUT: i64 = 60;

use std::{collections::{HashMap, HashSet}, mem};

use crate::common::Flow;

pub struct MeasurementCache {
    pub last_flush: time::Tm,
    pub flow_measures: HashMap<Flow, FlowMeasurement>,
    pub flow_measures_flushed: HashSet<Flow>,
}

pub struct FlowMeasurement {
    pub src_cc: Option<String>,
    pub dst_cc: Option<String>,
    pub server_port: u16,
    pub tcp_flags: Vec<i16>,
    pub ipid: Vec<i16>,
    pub ttl: Vec<i8>,
    pub last_updated: i64,
    pub start_time: i64,
}

impl MeasurementCache {
    pub fn new() -> MeasurementCache {
        MeasurementCache {
            last_flush: time::now(),
            flow_measures: HashMap::new(),
            flow_measures_flushed: HashSet::new(),
        }
    }

    pub fn add_measurement(&mut self, flow: &Flow, src_cc: Option<String>, dst_cc: Option<String>, tcp_flags: u16, ipid: u16, ttl: u8, server_port: u16) {
        if !self.flow_measures_flushed.contains(flow) {
            let mut measurement = FlowMeasurement {
                src_cc,
                dst_cc,
                server_port,
                tcp_flags: Vec::new(),
                ipid: Vec::new(),
                ttl: Vec::new(),
                last_updated: time::now().to_timespec().sec,
                start_time: time::now().to_timespec().sec,
            };
            measurement.tcp_flags.push(tcp_flags as i16);
            measurement.ipid.push(ipid as i16);
            measurement.ttl.push(ttl as i8);
            self.flow_measures.insert(*flow, measurement);
        }
    }

    pub fn update_measurement(&mut self, flow: &Flow, tcp_flags: u16, ipid: u16, ttl: u8) {
        if let Some(measurement) =  self.flow_measures.get_mut(flow) {
            measurement.tcp_flags.push(tcp_flags as i16);
            measurement.ipid.push(ipid as i16);
            measurement.ttl.push(ttl as i8);
            measurement.last_updated = time::now().to_timespec().sec;
        }
    }

    pub fn flush_measurements(&mut self) -> HashMap<Flow, FlowMeasurement> {
        self.last_flush = time::now();
        let mut measurements_ready = HashMap::<Flow, FlowMeasurement>::new();
        let mut measurement_flows = HashSet::<Flow>::new();
        let new_flush = HashSet::new();
        let curr_time = time::now().to_timespec().sec;
        for (flow, measurement) in self.flow_measures.iter_mut() {
            if curr_time - measurement.last_updated > TCP_CONNECTION_TIMEOUT {
                self.flow_measures_flushed.insert(*flow);
                measurement_flows.insert(*flow);
            }
        }
        for flow in measurement_flows {
            measurements_ready.insert(flow, self.flow_measures.remove(&flow).unwrap());
        }
        let _old_flush = mem::replace(&mut self.flow_measures_flushed, new_flush);
        return measurements_ready
    }
}