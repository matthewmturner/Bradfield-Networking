use std::convert::TryInto;
use std::net::UdpSocket;

#[derive(Debug)]
struct DnsHeader {
    tx_id: u16,
    msg_type: DnsHeaderType,
    opt_code: DnsOptCode,
    aa: bool,
    tc: bool,
    rd: bool,
    ra: bool,
    rcode: DnsResponseCode,
}

impl DnsHeader {
    fn from_bytes(bytes: [u8; 16]) -> DnsHeader {
        let mut bits = u128::from_be_bytes(bytes);
        let tx_mask = 0b1111_1111_1111_1111;
        let tx_id = (bits & tx_mask) as u16;
        bits >>= 16;
        let dns_type = match bits & 1 {
            0 => Ok(DnsHeaderType::Query),
            1 => Ok(DnsHeaderType::Response),
            _ => Err("Unexpected DNS type"),
        };
        let four_bit_mask = 0b1111_u128;
        let opt_code = match (bits >> 1) & four_bit_mask {
            0 => Ok(DnsOptCode::Query),
            1 => Ok(DnsOptCode::Iquery),
            2 => Ok(DnsOptCode::Status),
            3 => Ok(DnsOptCode::Future),
            _ => Err("Unexpected Opt Code"),
        };
        let aa = ((bits >> 5) & 1) != 0;
        let tc = ((bits >> 6) & 1) != 0;
        let rd = ((bits >> 7) & 1) != 0;
        let ra = ((bits >> 15) & 1) != 0; // Do I really need to add 8 since
                                          // its the next byte and little endian? I'm looking for the next bit
                                          // and expected to be able to use >> 8

        let response_code = match (bits >> 19) & four_bit_mask {
            0 => Ok(DnsResponseCode::NoError),
            1 => Ok(DnsResponseCode::FormatError),
            2 => Ok(DnsResponseCode::ServerFailure),
            3 => Ok(DnsResponseCode::NameError),
            4 => Ok(DnsResponseCode::NotImplemented),
            5 => Ok(DnsResponseCode::Refused),
            6 => Ok(DnsResponseCode::Future),
            _ => Err("Unexpected Response Code"),
        };
        DnsHeader {
            tx_id,
            msg_type: dns_type.expect("DNS Type Error"),
            opt_code: opt_code.expect("DNS Opt Code Error"),
            aa,
            tc,
            rd,
            ra,
            rcode: response_code.expect("DNS Response Code Error"),
        }
    }
}

#[derive(Debug)]
enum DnsHeaderType {
    Query = 0,
    Response = 1,
}

#[derive(Debug)]
enum DnsOptCode {
    Query = 0,
    Iquery = 1,
    Status = 2,
    Future = 3,
}

#[derive(Debug)]
enum DnsResponseCode {
    NoError = 0,
    FormatError = 1,
    ServerFailure = 2,
    NameError = 3,
    NotImplemented = 4,
    Refused = 5,
    Future = 6,
}

fn construct_dns_headerr(
    tx_id: u16,
    dns_type: DnsHeaderType,
    op_code: DnsOptCode,
    aa: u128,
    tc: u128,
    rd: u128,
    ra: u128,
    qdcount: u128,
) -> u128 {
    let mut header: u128 = tx_id as u128;

    header |= (dns_type as u128) << 9;
    header |= (op_code as u128) << 10;
    header |= aa << 14;
    header |= tc << 15;
    header |= rd << 16;
    header |= ra << 17;
    header |= qdcount << 40;
    header
}

fn convert_domain_to_questions(domain: String) -> Vec<u8> {
    let labels: Vec<&str> = domain.split('.').collect();
    let mut questions = Vec::new();
    for label in labels.iter() {
        let length = label.len();
        questions.push(length as u8);
        questions.extend_from_slice(label.as_bytes());
    }
    questions
}

fn main() -> std::io::Result<()> {
    {
        println!("1337 in bits: {:b}", 1337_u128);
        let local = "0.0.0.0:0";
        let google_dns = "8.8.8.8:53";
        let socket = UdpSocket::bind(local)?;

        let dns_type = DnsHeaderType::Query;
        let opt_code = DnsOptCode::Query;

        let domain = std::env::args().nth(1).expect("Misisng domain");
        let records = std::env::args().nth(2).unwrap_or_else(|| String::from("All"));

        println!("Domain: {}, Record: {}", domain, records);
        let header = construct_dns_headerr(7, dns_type, opt_code, 0, 0, 1, 0, 1);
        let mut full_buf = header.to_be_bytes();
        full_buf.reverse();
        let mut buf = Vec::new();
        buf.extend_from_slice(&full_buf[..12]);
        let questions = convert_domain_to_questions(domain);
        buf.extend_from_slice(&questions);
        buf.extend_from_slice(&[0, 0, 1, 0, 1]);

        println!("Buf bits: \n{:034b}", u128::from_be_bytes(full_buf));
        println!("Buf byte array: {:?}", buf);

        socket
            .send_to(&buf, google_dns)
            .expect("Couldnt send datat");
        let mut read_buf = [0; 64];
        let (number_of_bytes, src_addr) = socket
            .recv_from(&mut read_buf)
            .expect("Didn't receive data");
        println!("Read socket source address: {}", src_addr);
        println!("Read socket bytes read: {}", number_of_bytes);
        read_buf.reverse();
        println!("Filled buf:\n{:?}", read_buf);
        let header_bytes = &read_buf[48..]
            .try_into()
            .expect("Failed to get header bytes");
        let bits = u128::from_be_bytes(*header_bytes);
        println!("Reponse bits:\n{:b}", bits);
        let dns_response = DnsHeader::from_bytes(*header_bytes);
        println!("Response: {:?}", dns_response);

        let mut ip = vec![0; 4];

        let buf_size = read_buf.len();
        let ip_start = buf_size - number_of_bytes;
        let ip_bytes = &read_buf[ip_start..ip_start + 4];
        ip.clone_from_slice(&ip_bytes);
        ip.reverse();
        println!("Answer IP: {:?}", ip);
    }
    Ok(())
}
