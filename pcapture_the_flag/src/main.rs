use std::convert::TryInto;
use std::fs;

use eui48::MacAddress;

fn parse_pcap_header(pcap_bytes: &mut Vec<u8>) {
    let magic_number: Vec<u8> = pcap_bytes.drain(..4).collect();
    println!("Magic Number: {:x?}", magic_number);
    let major_version: Vec<u8> = pcap_bytes.drain(..2).collect();
    let minor_version: Vec<u8> = pcap_bytes.drain(..2).collect();
    println!(
        "Major.Minor Version: {:x?}.{:x?}",
        major_version, minor_version
    );
    let time_zone_offset: Vec<u8> = pcap_bytes.drain(..4).collect();
    println!("Time Zone Offset: {:x?}", time_zone_offset);
    let time_stamp_accuracy: Vec<u8> = pcap_bytes.drain(..4).collect();
    println!("Time Stamp Accuracy: {:x?}", time_stamp_accuracy);
    let snapshot_length: Vec<u8> = pcap_bytes.drain(..4).collect();
    println!("Snapshot Length: {:x?}", snapshot_length);
    let link_layer_type: Vec<u8> = pcap_bytes.drain(..4).collect();
    println!("Link Layer Header Type: {:x?}", link_layer_type);
}

fn extract_eth(pcap_packets: &mut Vec<u8>, captured_bytes: usize) {
    println!("***** Extracting Ethernet Header *****");
    let mac_destination_bytes: [u8; 6] = pcap_packets
        .drain(..6)
        .collect::<Vec<u8>>()
        .try_into()
        .expect("wrong");
    let mac_destination = MacAddress::new(mac_destination_bytes).to_canonical();
    let mac_source_bytes: [u8; 6] = pcap_packets
        .drain(..6)
        .collect::<Vec<u8>>()
        .try_into()
        .expect("wrong");
    let mac_source = MacAddress::new(mac_source_bytes).to_canonical();
    println!(
        "MAC Source:{:?}\nDestination:{:?}",
        mac_source, mac_destination
    );
    let ether_type: Vec<u8> = pcap_packets.drain(..2).collect();
    println!("Ether Type: {:?}", ether_type);
    let payload_bytes = captured_bytes - 6 - 6 - 2 - 4;
    println!("Payload bytes: {:?}", payload_bytes);
    let payload: Vec<u8> = pcap_packets.drain(..payload_bytes).collect();
    let frame_check: Vec<u8> = pcap_packets.drain(..4).collect();
    println!("Frame Check: {:?}", frame_check);
}

fn extract_packet(pcap_packets: &mut Vec<u8>) {
    println!("***** Extracting Packet *****");
    let capture_time: Vec<u8> = pcap_packets.drain(..4).collect();
    let capture_time_m: Vec<u8> = pcap_packets.drain(..4).collect();
    println!("Capture Time: {:?}:{:?}", capture_time, capture_time_m);
    let captured_bytes: [u8; 4] = pcap_packets
        .drain(..4)
        .collect::<Vec<u8>>()
        .try_into()
        .expect("Wrong");
    let captured_bytes_num = u32::from_le_bytes(captured_bytes);
    let total_bytes: [u8; 4] = pcap_packets
        .drain(..4)
        .collect::<Vec<u8>>()
        .try_into()
        .expect("Wrong");
    let total_bytes_num = u32::from_le_bytes(total_bytes);
    println!("Total Bytes: {:?}", captured_bytes_num);
    println!("Captured Bytes: {:?}", total_bytes_num);
    assert_eq!(captured_bytes_num, total_bytes_num);
    extract_eth(pcap_packets, captured_bytes_num as usize);
}

fn main() {
    let path = "net.cap";
    let mut data = fs::read(path).expect("Unable to read file");

    parse_pcap_header(&mut data);
    println!("");
    let mut n = 0;
    while !data.is_empty() {
        extract_packet(&mut data);
        n += 1;
        println!("Packet #{}\n", n);
    }
}
