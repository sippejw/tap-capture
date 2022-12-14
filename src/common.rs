use std::net::{IpAddr};
use std::hash::{Hash, Hasher};
use std::time::{Instant};

use memuse::DynamicUsage;
use pnet::packet::tcp::TcpPacket;
use pnet::packet::udp::UdpPacket;

#[derive(Copy, Clone)]
pub struct Flow {
    pub src_ip: IpAddr,
    pub dst_ip: IpAddr,
    pub src_port: u16,
    pub dst_port: u16,
}

impl Flow {
    pub fn new_tcp(src_ip: &IpAddr, dst_ip: &IpAddr, tcp_pkt: &TcpPacket) -> Flow {
        Flow {
            src_ip: *src_ip,
            dst_ip: *dst_ip,
            src_port: tcp_pkt.get_source(),
            dst_port: tcp_pkt.get_destination(),
        }
    }

    pub fn new_udp(src_ip: &IpAddr, dst_ip: &IpAddr, udp_pkt: &UdpPacket) -> Flow {
        Flow {
            src_ip: *src_ip,
            dst_ip: *dst_ip,
            src_port: udp_pkt.get_source(),
            dst_port: udp_pkt.get_destination(),
        }
    }

    pub fn reversed_clone(&self) -> Flow {
        Flow{src_ip: self.dst_ip,
            src_port: self.dst_port,
            dst_ip: self.src_ip,
            dst_port: self.src_port,
        }
    }
}

impl PartialEq for Flow {
    fn eq(&self, other: &Flow) -> bool {
        (self.src_ip == other.src_ip && self.dst_ip == other.dst_ip && self.src_port == other.src_port && self.dst_port == other.dst_port) ||
        (self.src_ip == other.dst_ip && self.dst_ip == other.src_ip && self.src_port == other.dst_port && self.dst_port == other.src_port)
    }
}

impl DynamicUsage for Flow {
    fn dynamic_usage(&self) -> usize {
        // Assuming worst case (IPv6 Addresses)
        return 4 + 4 + 16 + 16
    }
    fn dynamic_usage_bounds(&self) -> (usize, Option<usize>) {
        return (4+4+16+16, None);
    }
}

impl Eq for Flow {}

impl Hash for Flow {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.src_ip.hash(state);
        self.dst_ip.hash(state);
        self.src_port.hash(state);
        self.dst_port.hash(state);
    }
}

pub struct TimedFlow {
    pub event_time: Instant,
    pub flow: Flow,
}

impl DynamicUsage for TimedFlow {
    fn dynamic_usage(&self) -> usize {
        // Assuming worst case (IPv6 Addresses)
        return self.flow.dynamic_usage() + 16
    }
    fn dynamic_usage_bounds(&self) -> (usize, Option<usize>) {
        return (self.flow.dynamic_usage()+16, None);
    }
}
pub fn u8_to_u16_be(first_byte: u8, second_byte: u8) -> u16 {
    (first_byte as u16) << 8 | (second_byte as u16)
}

pub fn u8_to_u32_be(first_byte: u8, second_byte: u8, third_byte: u8, fourth_byte: u8) -> u32 {
    (first_byte as u32) << 24 | (second_byte as u32) << 16 | (third_byte as u32) << 8 | (second_byte as u32)
}
