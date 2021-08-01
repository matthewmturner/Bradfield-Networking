use std::fs;

use chrono::prelude::*;

fn main() {
    // Header Byte # 1
    // First 7 bits used to indicates day of week the was file constructed.
    // The index (0=Mon to 6=Sun) of the bit set to 1 is the day it was made.
    // The 8th bit indicates whether the file was created before or after
    // 12pm EST.

    let datetime_byte: u8;
    let base = 1;
    datetime_byte = (base << 7) | (base);

    // Header Byte # 2
    // Length of payload in bytes.
    // Payload can be from 1 to 255 bytes.
    let mut payload = String::new();
    println!("Enter payload: ");
    let mut payload_bytes = std::io::stdin().read_line(&mut payload).unwrap();

    if payload_bytes > 255 {
        println!("Payload must be no greater than 256 bytes / chars");
        println!("Enter payload: ");
        payload_bytes = std::io::stdin().read_line(&mut payload).unwrap();
    }

    // Remove newline from payload
    payload.pop();
    payload_bytes -= 1;

    println!("Payload length: {}\nPayload: {}", payload_bytes, payload);

    let mut output: Vec<u8> = Vec::new();
    println!("Adding Header #1 (Datetime): {:b}", datetime_byte);
    output.push(datetime_byte);
    println!(
        "Adding Header #2 (Payload length):\nDec: {}\nHex: {:x?}\nBits: {:b}",
        payload_bytes as u8, payload_bytes as u8, payload_bytes as u8
    );
    output.push(payload_bytes as u8);

    for c in payload.chars() {
        output.push(c as u8)
    }

    // Footer #1
    // 1 byte that shows the number of seconds that have elapsed
    // in the minute at the time footer is generated
    let min_seconds = Local::now().second() as u8;
    println!("Footer min seconds: {}", min_seconds);
    output.push(min_seconds);

    // Footer #2
    // 8 bytes that show the number of seconds that have elapsed
    // in the day that file was produced
    let day_start = Local::today().and_hms(0, 0, 0);
    let day_seconds = Local::now().timestamp() - day_start.timestamp();
    println!("Footer day seconds: {}", day_seconds);
    for &byte in day_seconds.to_ne_bytes().iter() {
        output.push(byte)
    }

    fs::write("matt.bin", output).unwrap();
}
