use std::env;
use std::str;
use std::net::UdpSocket;
use rand::prelude::*;
use std::io::{Cursor, Read};
use byteorder::{NetworkEndian, ReadBytesExt};

// IPv4 address of f.root-servers.net DNS root server
// Operated by Internet Systems Consortium, Inc.
// Source: https://root-servers.org/
const ROOT_SERVER_ADDR: &str = "192.5.5.241";
const DNS_PORT: u8 = 53;

// Source: https://datatracker.ietf.org/doc/html/rfc1035
const TYPE_A: u16 = 1;
const TYPE_NS: u16 = 2;
const TYPE_CNAME: u16 = 5;
const TYPE_SOA: u16 = 6;
const RCODE_NXDOMAIN: u16 = 3;
const CLASS_IN: u16 = 1;

// bitmasks
const RCODE_MASK: u16 = 0b00001111;
const COMPRESSION_MASK: u8 = 0b11000000;
const COMPRESSION_PTR_MASK: u8 = 0b00111111;

#[derive(Default)]
#[derive(Debug)]
pub struct DNSHeader {
    id: u16,
    flags: u16,
    num_questions: u16,
    num_answers: u16,
    num_authorities: u16,
    num_additionals: u16
}

#[derive(Debug)]
pub struct DNSQuestion {
    name: Vec<u8>,
    type_: u16,
    class: u16,
}

// Note: this implementation of a DNS resolver doesn't 
// use the NAME, CLASS & TTL fields, so we don't need to store those
#[derive(Debug)]
pub struct DNSRecord {
    type_: u16,
    data: Vec<u8>
}

#[derive(Debug)]
#[derive(Default)]
pub struct DNSPacket {
    header: DNSHeader,
    questions: Vec<DNSQuestion>,
    answers: Vec<DNSRecord>,
    authorities: Vec<DNSRecord>,
    additionals: Vec<DNSRecord>
}

impl DNSHeader {
    fn to_bytes(&self) -> Vec<u8> {
        [
            self.id.to_be_bytes(),
            self.flags.to_be_bytes(),
            self.num_questions.to_be_bytes(),
            self.num_answers.to_be_bytes(),
            self.num_authorities.to_be_bytes(),
            self.num_additionals.to_be_bytes()
        ].concat()
    }
}

impl DNSQuestion {
    fn to_bytes(&self) -> Vec<u8> {
        [
            self.name.to_vec(), 
            self.type_.to_be_bytes().to_vec(), 
            self.class.to_be_bytes().to_vec(),
        ].concat()
    }
}

fn generate_random_id() -> u16 {
    let seed: u64 = 1;
    let mut rng = StdRng::seed_from_u64(seed);
    rng.gen()
}

fn build_query(domain_name: &String, record_type: u16) -> Vec<u8> {
    let name = encode_dns_name(domain_name);
    let id: u16 = generate_random_id();
    const RECURSION_DESIRED: u16 = 1 << 8;
    
    let header = DNSHeader { 
        id: id, 
        num_questions: 1, 
        flags: RECURSION_DESIRED,
        ..Default::default()
    };
    let question = DNSQuestion { 
        name: name,
        type_: record_type,
        class: CLASS_IN
    };
    [header.to_bytes(), question.to_bytes()].concat()
}

fn encode_dns_name(name: &String) -> Vec<u8> {
    let parts = name.split(".");
    let mut encoded = Vec::<u8>::new();
    for part in parts {
        let len = part.len() as u8;
        encoded.extend_from_slice(&len.to_be_bytes());
        encoded.extend_from_slice(part.as_bytes());
    }
    encoded.push(0x0);
    encoded
}

fn decode_dns_name(reader: &mut Cursor<Vec<u8>>) -> Vec<u8> {
    let mut parts = Vec::<String>::new();
    let mut len = reader.read_u8().unwrap();
    while len != 0 {
        if len & COMPRESSION_MASK > 0 {
            parts.push(str::from_utf8(&decode_compressed_name(reader, len)).to_owned().unwrap().to_string());
            break;
        }
        let mut buf = vec![0u8; len.into()];
        let _ = reader.read_exact(&mut buf);
        parts.push(str::from_utf8(&buf).to_owned().unwrap().to_string());
        len = reader.read_u8().unwrap();
    }
    parts.join(".").as_bytes().to_vec()
}

fn decode_compressed_name(reader: &mut Cursor<Vec<u8>>, len: u8) -> Vec<u8> {
    let ptr_bytes = vec![len & COMPRESSION_PTR_MASK, reader.read_u8().unwrap()];
    let ptr = u16::from_be_bytes(ptr_bytes.try_into().unwrap());
    let cur_pos = reader.position();
    let _ = reader.set_position(ptr.into());
    let name = decode_dns_name(reader);
    let _ = reader.set_position(cur_pos);
    name
}

fn parse_header(reader: &mut Cursor<Vec<u8>>) -> DNSHeader {
    DNSHeader { 
        id: reader.read_u16::<NetworkEndian>().unwrap(),
        flags: reader.read_u16::<NetworkEndian>().unwrap(),
        num_questions: reader.read_u16::<NetworkEndian>().unwrap(),
        num_answers: reader.read_u16::<NetworkEndian>().unwrap(),
        num_authorities: reader.read_u16::<NetworkEndian>().unwrap(),
        num_additionals: reader.read_u16::<NetworkEndian>().unwrap()
    }
}

fn parse_question(reader: &mut Cursor<Vec<u8>>) -> DNSQuestion {
    DNSQuestion {
        name: decode_dns_name(reader),
        type_: reader.read_u16::<NetworkEndian>().unwrap(),
        class: reader.read_u16::<NetworkEndian>().unwrap()
    }
}

fn parse_record(reader: &mut Cursor<Vec<u8>>) -> DNSRecord {
    let _ = decode_dns_name(reader);
    let type_ = reader.read_u16::<NetworkEndian>().unwrap();
    let _ = reader.read_u16::<NetworkEndian>().unwrap(); // ignore CLASS field
    let _ = reader.read_u32::<NetworkEndian>().unwrap(); // ignore TTL field
    let data_len = reader.read_u16::<NetworkEndian>().unwrap();
    let mut data = vec![0u8; data_len.into()];

    if type_ == TYPE_NS || type_ == TYPE_CNAME || type_ == TYPE_SOA {
        data = decode_dns_name(reader);
    } else {
        let _ = reader.read_exact(&mut data);
    }
    
    DNSRecord { type_, data }
}

fn parse_dns_packet(data: &[u8]) -> DNSPacket {
    let mut reader = Cursor::new(data.to_vec());
    let mut packet = DNSPacket {
        header: parse_header(&mut reader),
        ..Default::default()
    };
    for _ in 0..packet.header.num_questions {
        packet.questions.push(parse_question(&mut reader));
    }
    for _ in 0..packet.header.num_answers {
        packet.answers.push(parse_record(&mut reader));
    }
    for _ in 0..packet.header.num_authorities {
        packet.authorities.push(parse_record(&mut reader));
    }
    for _ in 0..packet.header.num_additionals {
        packet.additionals.push(parse_record(&mut reader));
    }
    packet
}

fn ip_to_string(ip: &Vec<u8>) -> String {
    let mut ip_string = Vec::<String>::new();
    for part in ip {
        let part_base10 = *part as i32;
        ip_string.push(part_base10.to_string());
    }
    ip_string.join(".")
}

fn get_answer(packet: &DNSPacket) -> Option<&Vec<u8>> {
    for rec in &packet.answers {
        if rec.type_ == TYPE_A {
            return Some(&rec.data);
        }
    }
    None
}

fn get_nameserver_ip(packet: &DNSPacket) -> Option<String> {
    for rec in &packet.additionals {
        if rec.type_ == TYPE_A {
            return Some(ip_to_string(&rec.data));
        }
    }
    None
}

fn get_nameserver(packet: &DNSPacket) -> Option<String> {
    for rec in &packet.authorities {
        if rec.type_ == TYPE_NS {
            return Some(String::from_utf8(rec.data.to_vec()).unwrap());
        }
    }
    None
}

fn resolve(domain_name: &String, record_type: u16) -> Option<String> {
    let mut nameserver = ROOT_SERVER_ADDR.to_string();
    loop {
        println!("Querying nameserver {nameserver} for {domain_name}");
        let response = send_query(&nameserver, domain_name, record_type);
        match get_answer(&response) {
            Some(v) => return Some(ip_to_string(v)),
            None => {},
        };
        nameserver = match get_nameserver_ip(&response) {
            Some(v) => v,
            None => {
                match get_nameserver(&response) {
                    Some(name) => {
                        resolve(&name, TYPE_A).unwrap()
                    }
                    None => { 
                        let hdr = &response.header;
                        if hdr.num_answers > 0 && response.answers[0].type_ == TYPE_CNAME {
                            let canonical_name = &String::from_utf8(response.answers[0].data.to_vec()).unwrap();
                            return resolve(&canonical_name, TYPE_A);
                        } else if hdr.flags & RCODE_MASK == RCODE_NXDOMAIN {
                            return None;
                        } else if hdr.num_additionals == 0 && hdr.num_authorities > 0 && response.authorities[0].type_ == TYPE_SOA {
                            return None;
                        } else {
                            panic!("ERROR: Couldn't resolve the provided domain name.\
                            \nReceived {response:X?} from {nameserver}.");
                        }
                    }
                }
            }
        };
    };
}

fn send_query(ip_addr: &String, name: &String, type_: u16) -> DNSPacket {
    let query = build_query(&name, type_);
    let sock = UdpSocket::bind("0.0.0.0:0").expect("Failed to bind");
    sock.connect(format!("{ip_addr}:{DNS_PORT}")).expect(format!("Failed to connect to the server: {ip_addr}").as_str());
    sock.send(&query).expect("Failed to send query");
    let mut buffer = [0; 1024];
    let bytes_read = sock.recv(&mut buffer).expect("Failed to receive response");
    let response = parse_dns_packet(&buffer[..bytes_read]);
    response
}

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() != 2 { panic!("Usage: cargo run [domain name]") }
    let domain_name = &args[1];
    match resolve(domain_name, TYPE_A) {
        Some(ip_addr) => println!("IP address of {domain_name} is {ip_addr}"),
        None => println!("NXDOMAIN")
    };
}
