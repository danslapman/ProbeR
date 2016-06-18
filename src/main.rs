extern crate chrono;
extern crate net2;
#[macro_use] extern crate clap;

pub mod cc_checker;

use std::net::{Ipv4Addr, SocketAddrV4};
use chrono::Local;
use net2::{UdpBuilder, UdpSocketExt};
use clap::{Arg, App};

static MAX_PID_COUNT: usize = 8192;

fn show_message(level: &str, message: &str) {
    let time_string = Local::now().format("%d.%m.%Y %H:%M:%S");
    println!("[{}] {}: {}", time_string, level, message);
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
    let matches = App::new("ProbeR")
        .version("1.0")
        .about("MPEG-TS stream analyser utility")
        .author("Daniel Slapman <danslapman@gmail.com>")
        .arg(Arg::with_name("multicast group")
            .help("IP address representing multicast group")
            .required(true)
            .index(1))
        .arg(Arg::with_name("interface address")
            .help("IP address of network interface")
            .index(2))
        .arg(Arg::with_name("port")
            .help("Port to listen")
            .long("port")
            .short("p")
            .takes_value(true))
        .arg(Arg::with_name("sample length")
            .help("Length of sample (in packets)")
            .long("sl")
            .takes_value(true))
        .arg(Arg::with_name("once")
            .help("Sample once and quit")
            .long("once")
            .short("o"))
        .get_matches(); 
    
    let multicast_addr = value_t!(matches, "multicast group", Ipv4Addr).expect("Invalid value for multicast address!");
    let port = value_t!(matches, "port", u16).unwrap_or(1234);
    let interface_ip = value_t!(matches, "interface address", Ipv4Addr).unwrap_or(Ipv4Addr::new(0, 0, 0, 0));
    let stat_interval = value_t!(matches, "sample length", u32).unwrap_or(50000);
    let stat_interval_f = stat_interval as f32;
    let sample_once = matches.is_present("once");

    let mut pid_name: [Option<u16>; 8192] = [None; 8192];
    let mut pid_cc: [Option<u16>; 8192] = [None; 8192];
    let mut first_packet_received = false;
    let mut packets_received = 0u32;
    let mut last_stat_time = Local::now();

    let addr = SocketAddrV4::new(interface_ip, port);

	let socket_builder = UdpBuilder::new_v4().expect("Could not create builder");
	socket_builder.reuse_address(true).expect("Could not reuse address");

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
                    last_stat_time = Local::now();
                }
                process_packet(&msg_buff, &mut pid_name, &mut pid_cc);
                packets_received += 1;

                if packets_received == stat_interval {
                    let new_time = Local::now();
                    let delta = (new_time - last_stat_time).num_seconds() as f32;
                    let pps = stat_interval_f / delta;
                    let speed = ((stat_interval_f * 1316f32 / delta) / 1000f32) * 8f32;
                    show_message("INFO", format!("Bitrate: {} kbps. PPS: {} pps.", speed as i32, pps as i32).as_ref());
                    last_stat_time = new_time;
                    packets_received = 0;
                }
            }
        }
        
        if sample_once {
            break;
        }
    }
    
    drop(socket);
}