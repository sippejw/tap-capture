extern crate time;
extern crate postgres;
extern crate maxminddb;

use std::ops::Sub;
use std::time::{Duration, Instant};
use std::collections::{HashSet, VecDeque};
use maxminddb::{Reader, geoip2};
use pnet::packet::ethernet::{EthernetPacket, EtherTypes};
use pnet::packet::ipv6::Ipv6Packet;
use pnet::packet::Packet;
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::tcp::{TcpPacket, TcpFlags};
use rand::prelude::ThreadRng;
use std::net::IpAddr;
use log::{error, info};
use std::thread;
use postgres::{Client, NoTls};
use rand::Rng;
use std::io::Write;
use std::fs::OpenOptions;
use memuse::DynamicUsage;

use crate::cache::{MeasurementCache, MEASUREMENT_CACHE_FLUSH};
use crate::stats_tracker::StatsTracker;
use crate::common::{TimedFlow, Flow};

const CCDB_PATH: &str = "/usr/share/GeoIP/GeoLite2-Country.mmdb";

pub struct FlowTracker {
    flow_timeout: Duration,
    tcp_dsn: Option<String>,
    cache: MeasurementCache,
    pub stats: StatsTracker,
    tracked_tcp_flows: HashSet<Flow>,
    stale_tcp_drops: VecDeque<TimedFlow>,
    tracked_udp_flows: HashSet<Flow>,
    stale_udp_drops: VecDeque<TimedFlow>,
    prevented_udp_flows: HashSet<Flow>,
    stale_udp_preventions: VecDeque<TimedFlow>,
    rand: ThreadRng,
    cc_reader: Reader<Vec<u8>>,
    pub gre_offset: usize,
}

impl FlowTracker {
    pub fn new(tcp_dsn: Option<String>, core_id: i8, total_cores: i32, gre_offset: usize) -> FlowTracker {
        let mut ft = FlowTracker {
            flow_timeout: Duration::from_secs(20),
            tcp_dsn: tcp_dsn,
            cache: MeasurementCache::new(),
            stats: StatsTracker::new(),
            tracked_tcp_flows: HashSet::new(),
            stale_tcp_drops: VecDeque::with_capacity(65536),
            tracked_udp_flows: HashSet::new(),
            stale_udp_drops: VecDeque::with_capacity(65536),
            prevented_udp_flows: HashSet::new(),
            stale_udp_preventions: VecDeque::with_capacity(65536),
            rand: rand::thread_rng(),
            cc_reader: maxminddb::Reader::open_readfile(String::from(CCDB_PATH)).unwrap(),
            gre_offset: gre_offset,
        };

        ft.cache.last_flush = ft.cache.last_flush.sub(time::Duration::seconds(
            (core_id as i64) * MEASUREMENT_CACHE_FLUSH / (total_cores as i64)
        ));
        ft
    }

    pub fn log_packet(&mut self, contents: &String, file_path: &str) -> std::io::Result<()> {
        let mut file = OpenOptions::new()
        .write(true)
        .append(true)
        .open(file_path)?;
        file.write_all(contents.as_bytes())?;
        Ok(())
    }

    pub fn handle_ipv4_packet(&mut self, eth_pkt: &EthernetPacket) {
        self.stats.total_packets += 1;
        self.stats.ipv4_packets += 1;
        self.stats.bytes_processed += eth_pkt.packet().len() as u64;
        let ipv4_pkt = match eth_pkt.get_ethertype() {
            EtherTypes::Vlan => Ipv4Packet::new(&eth_pkt.payload()[4..]),
            _ => Ipv4Packet::new(eth_pkt.payload()),
        };
        if let Some(ipv4_pkt) = ipv4_pkt {
            match ipv4_pkt.get_next_level_protocol() {
                IpNextHeaderProtocols::Tcp => {
                    if let Some(tcp_pkt) = TcpPacket::new(&ipv4_pkt.payload()) {
                        self.handle_tcp_packet(
                            IpAddr::V4(ipv4_pkt.get_source()),
                            IpAddr::V4(ipv4_pkt.get_destination()),
                            &tcp_pkt,
                            ipv4_pkt.get_ecn(),
                            ipv4_pkt.get_identification(),
                            ipv4_pkt.get_ttl(),
                        )
                    }
                },
                _ => {}
            }
        }
    }

    pub fn handle_ipv6_packet(&mut self, eth_pkt: &EthernetPacket) {
        self.stats.total_packets += 1;
        self.stats.ipv6_packets += 1;
        self.stats.bytes_processed += eth_pkt.packet().len() as u64;
        let ipv6_pkt = match eth_pkt.get_ethertype() {
             EtherTypes::Vlan => Ipv6Packet::new(&eth_pkt.payload()[4..]),
             _ => Ipv6Packet::new(eth_pkt.payload()),
        };
        if let Some(ipv6_pkt) = ipv6_pkt {
            match ipv6_pkt.get_next_header() {
                IpNextHeaderProtocols::Tcp => {
                    if let Some(tcp_pkt) = TcpPacket::new(ipv6_pkt.payload()) {
                        self.handle_tcp_packet(
                            IpAddr::V6(ipv6_pkt.get_source()),
                            IpAddr::V6(ipv6_pkt.get_destination()),
                            &tcp_pkt,
                            ipv6_pkt.get_traffic_class() & 0b0000011,
                            0b00000000 as u16,
                            0b0000 as u8,
                        )
                    }
                },
                _ => return,
            }
        }
    }

    pub fn cc_lookup(&mut self, addr: IpAddr) -> Option<String> {
        let country: Option<geoip2::Country>= self.cc_reader.lookup(addr).unwrap_or(None);
        let mut cc: Option<String> = None;
        if let Some(country) = country {
            if let Some(valid_country) = country.country {
                if let Some(valid_iso) = valid_country.iso_code {
                    cc = Some(valid_iso.to_string());
                }
            }
        }
        return cc;
    }

    pub fn handle_tcp_packet(&mut self, source: IpAddr, destination: IpAddr, tcp_pkt: &TcpPacket, _ecn: u8, ipid: u16, ttl: u8) {
        self.stats.tcp_packets_seen += 1;
        let flow = Flow::new_tcp(&source, &destination, &tcp_pkt);
        let tcp_flags = tcp_pkt.get_flags();
        if (tcp_flags & TcpFlags::SYN) != 0 && (tcp_flags & TcpFlags::ACK) == 0 {
            // New TCP Flow
            self.stats.connections_seen += 1;
            if self.rand.gen_range(0..10) > -1 {
                // Allows for random sampling of TCP flows
                self.stats.connections_started += 1;
                self.begin_tracking_tcp_flow(&flow, tcp_pkt.packet().to_vec());


                let src_cc = self.cc_lookup(source);
                let dst_cc = self.cc_lookup(destination);
                self.cache.add_measurement(&flow, src_cc, dst_cc, tcp_flags, ipid, ttl, tcp_pkt.get_destination());
            }
            return
        }
        if (tcp_flags & TcpFlags::SYN) != 0 && (tcp_flags & TcpFlags::ACK) != 0 {
            if self.tracked_tcp_flows.contains(&flow.reversed_clone()) {
                // Server response to 3-way handshake (SYN ACK)
                self.cache.update_measurement(&flow.reversed_clone(), tcp_flags, ipid, ttl);
            }
            return
        }
        if (tcp_flags & TcpFlags::FIN) != 0 || (tcp_flags & TcpFlags::RST) != 0 {
            if self.tracked_tcp_flows.contains(&flow) {
                // Client closed the connection
                self.cache.update_measurement(&flow, tcp_flags, ipid, ttl);
            } else if self.tracked_tcp_flows.contains(&flow.reversed_clone()) {
                // Server closed the connection
                self.cache.update_measurement(&flow.reversed_clone(), tcp_flags, ipid, ttl);
            }
            // self.tracked_tcp_flows.remove(&flow);
            self.stats.connections_closed += 1;
            return
        }
        if self.tracked_tcp_flows.contains(&flow) {
            // Client data packet
            self.cache.update_measurement(&flow, tcp_flags, ipid, ttl);
        } else if self.tracked_tcp_flows.contains(&flow.reversed_clone()) {
            // Server data packet
            self.cache.update_measurement(&flow.reversed_clone(), tcp_flags, ipid, ttl);
        }
        // once in a while -- flush everything
        if time::now().to_timespec().sec - self.cache.last_flush.to_timespec().sec >
            MEASUREMENT_CACHE_FLUSH {
            self.flush_to_db()
        }
    }

    pub fn flush_to_db(&mut self) {

        let measurement_cache = self.cache.flush_measurements();

        if self.tcp_dsn != None {
            let tcp_dsn = self.tcp_dsn.clone().unwrap();
            thread::spawn(move || {
                let inserter_thread_start = time::now();
                let mut thread_db_conn = Client::connect(&tcp_dsn, NoTls).unwrap();

                let insert_tcp_measurement = match thread_db_conn.prepare(
                    "INSERT
                    INTO ecn_measurements (
                        start_time,
                        last_updated,
                        server_port,
                        src_cc,
                        dst_cc,
                        tcp_flags,
                        ipid,
                        ttl
                    VALUES ($1, $2, $3, $4, $5, $6, $7, $8);"
                )
                {
                    Ok(stmt) => stmt,
                    Err(e) => {
                        error!("Preparing insert_measurement failed: {}", e);
                        return
                    }
                };
                for (_k, measurement) in measurement_cache {
                    let updated_rows = thread_db_conn.execute(&insert_tcp_measurement, &[
                        &(measurement.start_time), 
                        &(measurement.last_updated), 
                        &(measurement.server_port as i16),
                        &(measurement.src_cc),
                        &(measurement.dst_cc),
                        &(measurement.tcp_flags),
                        &(measurement.ipid),
                        &(measurement.ttl),
                    ]);
                    if updated_rows.is_err() {
                        error!("Error updating TCP ECN measurements: {:?}", updated_rows);
                    }
                }

                let inserter_thread_end = time::now();
                info!("Updating TCP DB took {:?} ns in separate thread",
                         inserter_thread_end.sub(inserter_thread_start).num_nanoseconds());
            });
        }
    }

    fn begin_tracking_tcp_flow(&mut self, flow: &Flow, _syn_data: Vec<u8>) {
        // Always push back, even if the entry was already there. Doesn't hurt
        // to do a second check on overdueness, and this is simplest.
        self.stale_tcp_drops.push_back(TimedFlow {
            event_time: Instant::now(),
            flow: *flow,
        });
        self.tracked_tcp_flows.insert(*flow);
    }

    pub fn cleanup(&mut self) {
        while !self.stale_tcp_drops.is_empty() &&
            self.stale_tcp_drops.front().unwrap().event_time.elapsed() >= self.flow_timeout {
            let cur = self.stale_tcp_drops.pop_front().unwrap();
            self.tracked_tcp_flows.remove(&cur.flow);
        }
        while !self.stale_udp_drops.is_empty() &&
            self.stale_udp_drops.front().unwrap().event_time.elapsed() >= self.flow_timeout {
            let cur = self.stale_udp_drops.pop_front().unwrap();
            self.tracked_udp_flows.remove(&cur.flow);
        }
        while !self.stale_udp_preventions.is_empty() &&
            self.stale_udp_preventions.front().unwrap().event_time.elapsed() >= self.flow_timeout {
            let cur = self.stale_udp_preventions.pop_front().unwrap();
            self.prevented_udp_flows.remove(&cur.flow);
        }
    }

    pub fn debug_print(&mut self) {
        info!("tracked_tcp_flows: {} stale__tcp_drops: {}", self.tracked_tcp_flows.dynamic_usage(), self.stale_tcp_drops.dynamic_usage());
        info!("tracked_udp_flows: {} stale__udp_drops: {}", self.tracked_udp_flows.dynamic_usage(), self.stale_udp_drops.dynamic_usage());
        info!("Size of UDP Preventions: {}, Size of UDP Preventions Flush: {}", self.prevented_udp_flows.dynamic_usage(), self.stale_udp_preventions.dynamic_usage());
    }
}
