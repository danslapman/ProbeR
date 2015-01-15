extern crate time;

use std::os;
use std::io::net::udp::UdpSocket;
use std::io::net::ip::SocketAddr;
use std::io::net::ip::IpAddr;
use std::num::ToPrimitive;
use time::*;

static PACKET_STATISTICS_INTERVAL: i32 = 50000;

fn get_pid_cc(pid_name: &[u16], pid_cc: &[u16], pid: u16) -> u16 {
    for i in range(0us, 10) {
        if pid_name[i] == pid {
            return pid_cc[i];
        }
    }
    return -1;
}

fn set_pid_cc(pid_name: &mut[u16], pid_cc: &mut[u16], pid: u16, cc: u16) {
    let mut index = -1i16;
    for i in range(0us, 10) {
        if pid_name[i] == pid {
            index = i as i16;
            break;
        }
    }
    if index == -1i16 {
        for i in range(0us, 10) {
            if pid_name[i] == -1 {
                index = i as i16;
                pid_name[i] = pid;
                break;
            }
        }
    }
    if index == -1 {
        panic!("PID array is full");
    }
    pid_cc[index as usize] = cc;
}

fn process_packet(packet: &[u8], pid_name: &mut[u16], pid_cc: &mut[u16]) {
    let mut payload;
    let mut pid: u16;
    let mut cc: u16;
    let mut scrambled;
    let mut position = 0;
    let mut last_cc: u16;
    while position + 187 < 1316 {
        payload = (packet[position + 3] & 16) != 0;
        pid = 256 * (packet[position + 1] as u16 & 0x1f) + packet[position + 2] as u16;
        cc = packet[position + 3] as u16 & 0x0f;
        scrambled = (packet[position + 3] & 192) != 0;
        if packet[position] != 71 {
            continue;
        }
        last_cc = get_pid_cc(pid_name, pid_cc, pid);
        if last_cc != -1 {
            if 16 <= pid && pid <= 8190 && cc != last_cc && (last_cc != 15 && cc != 0) && payload {
                println!("CC Error in PID: {}, LastCC: {}, CC: {}", pid, last_cc, cc);
            }
            if scrambled {
                println!("Scrambled packet");
            }
        }
        set_pid_cc(pid_name, pid_cc, pid, cc);
        position += 188;
    }
}

fn main() {
    let args = os::args();
    if args.len() != 3 {
        println!("Usage:");
        println!("prober <multicast_group> <interface_ip>");
        return;
    }

    let multicast_addr: IpAddr = args[1].as_slice().parse().expect("Invalid value for multicast address!");
    let interface_addr: IpAddr = args[2].as_slice().parse().expect("Invalid value for interface address!");

    let mut pid_name: [u16; 10] = [0u16; 10];
    let mut pid_cc: [u16; 10] = [0u16; 10];
    let mut first_packet_received = false;
    let mut packets_received = 0i32;
    let mut last_stat_time = now().to_timespec();

    let addr = SocketAddr{ ip: interface_addr, port: 1234 };

    let mut socket = match UdpSocket::bind(addr) {
        Ok(s) => s,
        Err(e) => panic!("couldn't bind socket: {}", e),
    };

    let join_res = socket.join_multicast(multicast_addr);
    match join_res {
        Err(e) => {
            println!("Join error: {}", e);
            return;
        },
        _ => println!("Joined successfully")
    }

    let mut msg_buff = [0u8; 1316];

    loop {
        let data = socket.recv_from(&mut msg_buff);
        match data {
            Err(e) => {
                println!("Error receiving data: {}", e);
                if first_packet_received {break;}
            },
            Ok((amount, _)) => {
                println!("Received {} bytes", amount);
                if !first_packet_received {
                    first_packet_received = true;
                    last_stat_time = now().to_timespec();
                }
                process_packet(&msg_buff, &mut pid_name, &mut pid_cc);
                packets_received += 1;

                if packets_received == PACKET_STATISTICS_INTERVAL {
                    let new_time = now().to_timespec();
                    let delta = (new_time - last_stat_time).num_milliseconds().to_i32().unwrap();
                    let pps = PACKET_STATISTICS_INTERVAL / delta;
                    let speed = ((PACKET_STATISTICS_INTERVAL * 1316 / delta) / 1000) * 8;
                    println!("Bitrate: {} Mbps. PPS: {} pps.", speed, pps);
                    last_stat_time = new_time;
                    packets_received = 0;
                }
            }
        }
    }

    drop(socket);
}