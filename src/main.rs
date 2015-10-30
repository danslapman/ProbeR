extern crate time;
extern crate net2;

use std::env;
use std::net::{Ipv4Addr, SocketAddrV4};
use time::*;
use net2::{UdpBuilder, UdpSocketExt};

static PACKET_STATISTICS_INTERVAL: u32 = 50000;
static MAX_PID_COUNT: usize = 8192;

fn show_message(level: &str, message: &str) {
    let time_string = time::strftime("%d.%m.%Y %H:%M:%S", &now()).unwrap();
    println!("{} {}: {}", time_string, level, message);
}

fn get_pid_cc(pid_name: &[Option<u16>], pid_cc: &[Option<u16>], pid: u16) -> Option<u16> {
    for i in 0usize..MAX_PID_COUNT {
        if pid_name[i].is_some() && pid_name[i].unwrap() == pid {
            return pid_cc[i];
        }
    }
    return None;
}

fn set_pid_cc(pid_name: &mut[Option<u16>], pid_cc: &mut[Option<u16>], pid: u16, cc: u16) {
    let mut index: Option<usize> = None; 
    for i in 0usize..MAX_PID_COUNT {
        if pid_name[i].is_some() && pid_name[i].unwrap() == pid {
            index = Some(i);
            break;
        }
    }
    if index.is_none() {
        for i in 0usize..MAX_PID_COUNT {
            if pid_name[i].is_none() {
                index = Some(i);
                pid_name[i] = Some(pid);
                break;
            }
        }
    }
    pid_cc[index.expect("PID array is full")] = Some(cc);
}

fn process_packet(packet: &[u8], pid_name: &mut[Option<u16>], pid_cc: &mut[Option<u16>]) {
    let mut payload;
    let mut pid: u16;
    let mut cc: u16;
    let mut scrambled;
    let mut position = 0;
    let mut last_cc: Option<u16>;
    while position + 187 < 1316 {
        payload = (packet[position + 3] & 16) == 16;
        pid = 256 * (packet[position + 1] as u16 & 0x1f) + packet[position + 2] as u16;
        cc = packet[position + 3] as u16 & 0x0f;
        scrambled = (packet[position + 3] & 192) != 0;
        if packet[position] != 71 {
            continue;
        }
        last_cc = get_pid_cc(pid_name, pid_cc, pid);
        if last_cc.is_some() {
            let lcc = last_cc.unwrap();
            if 16 <= pid && pid <= 8190 && cc != lcc + 1 && (lcc != 15 && cc != 0) && payload {
                show_message("ERROR", format!("CC Error in PID: {}, LastCC: {}, CC: {}", pid, lcc, cc).as_ref());
            }
            if scrambled {
                show_message("ERROR", format!("Scrambled packet. PID: {}", pid).as_ref());
            }
        }
        set_pid_cc(pid_name, pid_cc, pid, cc);
        position += 188;
    }
}

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() != 2 && args.len() != 3 {
        println!("Usage:");
        println!("prober <multicast_group> (<interface_ip>)");
        return;
    }

    let multicast_addr: Ipv4Addr = match args[1].trim().parse() {
        Ok(addr) => addr,
        Err(_) => panic!("Invalid value for multicast address!")
    };

    let interface_ip: Ipv4Addr;

    if args.len() == 3 {
        let iface_ip_addr = match args[2].trim().parse() {
            Ok(addr) => addr,
            Err(_) => panic!("Invalid value for interface IP!")
        };
        interface_ip = iface_ip_addr;
    } else {
    	interface_ip = Ipv4Addr::new(0, 0, 0, 0);
    }

    let mut pid_name: [Option<u16>; 8192] = [None; 8192];
    let mut pid_cc: [Option<u16>; 8192] = [None; 8192];
    let mut first_packet_received = false;
    let mut packets_received = 0u32;
    let mut last_stat_time = now().to_timespec();

    let addr = SocketAddrV4::new(interface_ip, 1234);

	let socket_builder = UdpBuilder::new_v4().expect("Could not create builder!");
	socket_builder.reuse_address(true).expect("Could to reuse address");

    let socket = match socket_builder.bind(addr) {
        Ok(s) => s,
        Err(e) => panic!("couldn't bind socket: {}", e),
    };
    
    socket.set_read_timeout_ms(Some(5000)).expect("Could not set read timeout");
	
    let join_res = socket.join_multicast_v4(&multicast_addr, &interface_ip);
    match join_res {
        Err(e) => {
            show_message("ERROR", format!("Join error: {}", e).as_ref());
            return;
        },
        _ => show_message("INFO", "Joined successfully")
    }

    let mut msg_buff = [0u8; 1316];
    loop {
        let data = socket.recv_from(&mut msg_buff);
        match data {
            Err(e) => {
                show_message("ERROR", format!("Error receiving data: {}", e).as_ref());
            },
            Ok((_, _)) => {
                if !first_packet_received {
                    show_message("INFO", "First packet received");
                    first_packet_received = true;
                    last_stat_time = now().to_timespec();
                }
                process_packet(&msg_buff, &mut pid_name, &mut pid_cc);
                packets_received += 1;

                if packets_received == PACKET_STATISTICS_INTERVAL {
                    let new_time = now().to_timespec();
                    let delta = (new_time - last_stat_time).num_seconds() as u32;
                    let pps = PACKET_STATISTICS_INTERVAL / delta;
                    let speed = ((PACKET_STATISTICS_INTERVAL * 1316 / delta) / 1000) * 8;
                    show_message("INFO", format!("Bitrate: {} kbps. PPS: {} pps.", speed, pps).as_ref());
                    last_stat_time = new_time;
                    packets_received = 0;
                }
            }
        }
    }

    drop(socket);
}