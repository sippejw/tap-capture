extern crate time;
extern crate postgres;

use std::ops::Sub;
use std::time::{Duration, Instant};
use std::collections::{HashSet, VecDeque};
use pnet::packet::ethernet::{EthernetPacket, EtherTypes};
use pnet::packet::ipv6::Ipv6Packet;
use pnet::packet::udp::UdpPacket;
use pnet::packet::{Packet};
use pnet::packet::ipv4::{Ipv4Packet};
use pnet::packet::ip::{IpNextHeaderProtocols};
use pnet::packet::tcp::{TcpPacket, TcpFlags, TcpOptionNumber};
use rand::prelude::ThreadRng;
use std::net::{IpAddr};
use log::{error, info};
use std::{thread};
use postgres::{Client, NoTls};
use rand::Rng;
use std::io::Write;
use std::fs::OpenOptions;
use memuse::DynamicUsage;
use hex;

use crate::cache::{MeasurementCache, MEASUREMENT_CACHE_FLUSH};
use crate::stats_tracker::{StatsTracker};
use crate::common::{TimedFlow, Flow};

pub const BITS_PER_BYTE_LOWER: f64 = 0.425;
pub const BITS_PER_BYTE_UPPER: f64 = 0.575;

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
    tracked_quic_conns: HashSet<Flow>,
    stale_quic_drops: VecDeque<TimedFlow>,
    rand: ThreadRng,
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
            tracked_quic_conns: HashSet::new(),
            stale_quic_drops: VecDeque::with_capacity(65536),
            rand: rand::thread_rng(),
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
        if !self.byte_check(eth_pkt.payload()) && !self.entropy_check(eth_pkt.payload()) && eth_pkt.payload().len() >= 120 {
            if rand::random::<i32>() % 1000 == 0 {
                self.log_packet(&format!("{}\n", hex::encode(eth_pkt.payload())), "logs/network_layer_payloads.txt");
            }
        }
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
                        )
                    }
                },
                IpNextHeaderProtocols::Udp => {
                    if let Some(udp_pkt) = UdpPacket::new(&ipv4_pkt.payload()) {
                        self.handle_udp_packet(
                            IpAddr::V4(ipv4_pkt.get_source()),
                            IpAddr::V4(ipv4_pkt.get_destination()),
                            &udp_pkt,
                            ipv4_pkt.get_ecn(),
                        )
                    }
                }
                _ => {}
            }
        }
    }

    // Returns true if the payload is likely to be encrypted
    pub fn entropy_check(&mut self, payload: &[u8]) -> bool {
        let mut total_bits = 0; // Count of total number of bits seen
        let mut one_bits = 0; // Count of bits with value 1

        for i in payload {
            total_bits += 8;
            one_bits += i.count_ones();
        }

        let percent_ones = one_bits as f64 / total_bits as f64;
        if percent_ones > BITS_PER_BYTE_LOWER && percent_ones < BITS_PER_BYTE_UPPER {
            return true;
        }
        return false;
    }

    pub fn byte_check(&mut self, payload: &[u8]) -> bool {
        let search_bytes: &[&[u8]] = &[
            &[0x5b, 0x5d, 0x41, 0x5c, 0x41, 0x5d, 0x41, 0x5e, 0x41, 0x5f],
            &[0x5d, 0x41, 0x5c, 0x41, 0x5d, 0x41, 0x5e, 0x41, 0x5f, 0xc3],
            &[0xc8, 0x66, 0x0f, 0xd7, 0xd1, 0x81, 0xea, 0xff, 0xff, 0x00],
            &[0x66, 0x0f, 0xf8, 0xc8, 0x66, 0x0f, 0xd7, 0xd1, 0x81, 0xea],
            &[0x0f, 0xf8, 0xc8, 0x66, 0x0f, 0xd7, 0xd1, 0x81, 0xea, 0xff],
            &[0xf8, 0xc8, 0x66, 0x0f, 0xd7, 0xd1, 0x81, 0xea, 0xff, 0xff],
            &[0xca, 0x66, 0x0f, 0xf8, 0xc8, 0x66, 0x0f, 0xd7, 0xd1, 0x81],
            &[0xc2, 0x48, 0x8d, 0x52, 0x10, 0x66, 0x0f, 0xd7, 0xc0, 0x48],
            &[0x48, 0x8d, 0x52, 0x10, 0x66, 0x0f, 0xd7, 0xc0, 0x48, 0x8d],
            &[0x8d, 0x52, 0x10, 0x66, 0x0f, 0xd7, 0xc0, 0x48, 0x8d, 0x49],
        ];
        let mut search_index = [0];
        for b in payload {
            for i in 0 .. search_index.len() {
                if *b == search_bytes[i][search_index[i]] {
                    search_index[i] += 1;
                    if search_index[i] == search_bytes.len() {
                        self.log_packet(&format!("{}\n", hex::encode(payload)), "logs/binary_payloads.txt");
                        return true;
                    }
                } else {
                    search_index[i] = 0;
                }
            }
        }
        return false;
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
                        )
                    }
                },
                IpNextHeaderProtocols::Udp => {
                    if let Some(udp_pkt) = UdpPacket::new(&ipv6_pkt.payload()) {
                        self.handle_udp_packet(
                            IpAddr::V6(ipv6_pkt.get_source()),
                            IpAddr::V6(ipv6_pkt.get_destination()),
                            &udp_pkt,
                            ipv6_pkt.get_traffic_class() & 0b0000011,
                        )
                    }
                },
                IpNextHeaderProtocols::Udp => {
                    if let Some(udp_pkt) = UdpPacket::new(&ipv6_pkt.payload()) {
                        self.handle_udp_packet(
                            IpAddr::V6(ipv6_pkt.get_source()),
                            IpAddr::V6(ipv6_pkt.get_destination()),
                            &udp_pkt,
                            ipv6_pkt.get_traffic_class() & 0b0000011,
                        )
                    }
                }
                _ => return,
            }
        }
    }

    pub fn handle_udp_packet(&mut self, source: IpAddr, destination: IpAddr, udp_pkt: &UdpPacket, ecn: u8) {
        self.stats.udp_packets_seen += 1;
        let flow = Flow::new_udp(&source, &destination, &udp_pkt);
        if self.tracked_udp_flows.contains(&flow) {
            // Packets coming from client
        } else if self.tracked_udp_flows.contains(&flow.reversed_clone()) {
            // Packets coming from server
        } else {
            // New flow
            if self.rand.gen_range(0..10) > -1 {
                // Allows for random sampling of UDP flows
                self.begin_tracking_udp_flow(&flow);
            } else {
                self.prevent_tracking_udp_flow(&flow);
            }
        }
        if udp_pkt.payload().len() == 0 {
            return;
        }

        if self.byte_check(udp_pkt.payload()) {
            self.stats.udp_payloads_matched += 1;
        }

        match (udp_pkt.get_destination(), udp_pkt.get_source()) {
            (_, _) => {},
        }

    }

    pub fn handle_tcp_packet(&mut self, source: IpAddr, destination: IpAddr, tcp_pkt: &TcpPacket, ecn: u8) {
        self.stats.tcp_packets_seen += 1;
        let flow = Flow::new_tcp(&source, &destination, &tcp_pkt);
        let tcp_flags = tcp_pkt.get_flags();
        for option in tcp_pkt.get_options_iter() {
            // Iterates over each tcp pkt option
        }
        if (tcp_flags & TcpFlags::SYN) != 0 && (tcp_flags & TcpFlags::ACK) == 0 {
            // New TCP Flow
            self.stats.connections_seen += 1;
            if self.rand.gen_range(0..10) > -1 {
                // Allows for random sampling of TCP flows
                self.stats.connections_started += 1;
                self.begin_tracking_tcp_flow(&flow, tcp_pkt.packet().to_vec());
            }
            return
        }
        if (tcp_flags & TcpFlags::SYN) != 0 && (tcp_flags & TcpFlags::ACK) != 0 {
            if self.tracked_tcp_flows.contains(&flow.reversed_clone()) {
                // Server response to 3-way handshake (SYN ACK)
            }
            return
        }
        if (tcp_flags & TcpFlags::FIN) != 0 || (tcp_flags & TcpFlags::RST) != 0 {
            if self.tracked_tcp_flows.contains(&flow) {
                // Client closed the connection
            } else if self.tracked_tcp_flows.contains(&flow.reversed_clone()) {
                // Server closed the connection
            }
            self.tracked_tcp_flows.remove(&flow);
            self.stats.connections_closed += 1;
            return
        }
        if tcp_pkt.payload().len() == 0 {
            return
        }
        if self.byte_check(tcp_pkt.payload()) {
            self.stats.tcp_payloads_matched += 1;
        }
        if self.tracked_tcp_flows.contains(&flow) {
            // Client data packet
        } else if self.tracked_tcp_flows.contains(&flow.reversed_clone()) {
            // Server data packet
        }
        // once in a while -- flush everything
        if time::now().to_timespec().sec - self.cache.last_flush.to_timespec().sec >
            MEASUREMENT_CACHE_FLUSH {
            self.flush_to_db()
        }
    }

    pub fn flush_to_db(&mut self) {

        if self.tcp_dsn != None {
            let tcp_dsn = self.tcp_dsn.clone().unwrap();
            thread::spawn(move || {
                let inserter_thread_start = time::now();
                let mut thread_db_conn = Client::connect(&tcp_dsn, NoTls).unwrap();
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

    fn begin_tracking_udp_flow(&mut self, flow: &Flow) {
        // Always push back, even if the entry was already there. Doesn't hurt
        // to do a second check on overdueness, and this is simplest.
        self.stale_udp_drops.push_back(TimedFlow {
            event_time: Instant::now(),
            flow: *flow,
        });
        self.tracked_udp_flows.insert(*flow);
    }

    fn prevent_tracking_udp_flow(&mut self, flow: &Flow) {
        self.stale_udp_preventions.push_back(TimedFlow {
            event_time: Instant::now(),
            flow: *flow,
        });
        self.prevented_udp_flows.insert(*flow);
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
