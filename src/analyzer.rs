use anyhow::{anyhow, Result};
use nom::{
    branch::alt,
    bytes::complete::{tag, take},
    multi::{many0, many1},
    number::complete::{le_u16, le_u32, u8},
    IResult,
};
use std::{
    num::Wrapping,
    process::{Command, Stdio},
};

use crate::display::TapeDisplay;

pub fn analyze_tcp_data(data: &[u8]) -> Result<()> {
    println!("Size: {}", data.len());
    let mut i = 0;
    let mut num_data_rows = 0;
    while i < data.len() {
        match data[i] {
            0x1b => match data[i + 1] {
                0x7b => {
                    let payload_data = &data[i..i + 3 + data[i + 2] as usize];
                    println!("{payload_data:?}");
                    i += payload_data.len();
                    let mut payload_data = &payload_data[3..];

                    if payload_data.last().unwrap() != &0x7d {
                        return Err(anyhow!(
                            "Unexpected label data (not 0x7d): {:?}...",
                            &data[i..i + 16]
                        ));
                    }
                    payload_data.take_last();

                    if payload_data
                        .iter()
                        .map(|v| Wrapping(*v))
                        .sum::<Wrapping<u8>>()
                        .0
                        != payload_data.last().unwrap().wrapping_mul(2)
                    {
                        return Err(anyhow!(
                            "Unexpected label data (csum invalid): {:?}...",
                            &data[i..i + 16]
                        ));
                    }
                    // so the last byte of the payload_data is the checksum
                    payload_data.take_last();
                    if payload_data[0] == 76 {
                        let mut tape_len_bytes = [0u8; 4];
                        tape_len_bytes.copy_from_slice(&payload_data[1..5]);
                        let tape_len = u32::from_le_bytes(tape_len_bytes);
                        println!("cmd 0x1b 0x7b, {payload_data:?} tape_len = {}", tape_len);
                    } else {
                        println!("cmd 0x1b 0x7b, {payload_data:?}");
                    }
                }
                0x2e => {
                    if data[i + 2..i + 6] != [0, 0, 0, 1] {
                        return Err(anyhow!("Unexpected label data: {:?}...", &data[i..i + 16]));
                    }
                    let bits = data[i + 6] as usize + data[i + 7] as usize * 256;
                    let bytes = (bits + 7) / 8;
                    print!("cmd 0x1b 0x2e, bits = {bits}, bytes = {bytes}: ",);
                    let img_data = &data[i + 8..i + 8 + bytes];
                    for byte in img_data {
                        print!("{byte:08b}");
                    }
                    println!();
                    i += 8 + bytes;
                    num_data_rows += 1;
                }
                _ => {
                    return Err(anyhow!("Unexpected label data: {:?}...", &data[i..i + 16]));
                }
            },
            0x0c => {
                println!("cmd 0x0c (data end marker?)",);
                i += 1;
            }
            _ => {
                return Err(anyhow!("Unexpected label data: {:?}...", &data[i..]));
            }
        }
    }
    println!("num_data_rows = {}", num_data_rows);
    Ok(())
}

enum Direction {
    Source,
    Destination,
}

fn extract_data_from_btsnooplog(
    dump_file: &str,
    printer_address: &str,
    direction: Direction,
) -> Vec<u8> {
    // extract btspp packet from btsnoop log
    let dir = match direction {
        Direction::Source => "src",
        Direction::Destination => "dst",
    };
    let bluetooth_filter = format!("bluetooth.{} == {}", dir, printer_address);
    let tshark = Command::new("tshark")
        .args(["-r", dump_file])
        .args(["-R", "btspp"])
        .args(["-2", "-Y", &bluetooth_filter])
        .args(["-T", "json"])
        .stdout(Stdio::piped())
        .spawn()
        .expect("failed to execute tshark");
    let jq = Command::new("jq")
        .stdin(Stdio::from(tshark.stdout.unwrap()))
        .arg(".[]._source.layers.btspp.\"btspp.data\"")
        .arg("-r")
        .stdout(Stdio::piped())
        .spawn()
        .expect("failed to execute jq");
    let output = jq.wait_with_output().unwrap();
    let bytes = std::str::from_utf8(&output.stdout)
        .unwrap()
        .strip_suffix("\n")
        .unwrap()
        .replace("\n", ":");

    bytes
        .split(':')
        .map(|hex| u8::from_str_radix(hex, 16).unwrap())
        .collect()
}

pub fn analyze_btspp_data(dump_file: &str, address: &str) -> Result<()> {
    // send
    let data = extract_data_from_btsnooplog(dump_file, address, Direction::Destination);
    let (_, packets) = parse_printer_packets(&data).unwrap();
    println!("send packets");
    for p in packets {
        println!("{:02x?}", p);
    }

    // ack
    let data = extract_data_from_btsnooplog(dump_file, address, Direction::Source);
    let (_, packets) = parse_printer_packets(&data).unwrap();
    println!("ack packets");
    for p in packets {
        println!("{:02x?}", p);
    }

    Ok(())
}

pub trait ToBytes {
    fn to_bytes(&self) -> Vec<u8>;
}

#[derive(Debug)]
pub enum PrinterProtocol {
    Command(PrinterCommand),
    PrintData(PrinterPrintData),
    Response(PrinterResponse),
}

impl ToBytes for PrinterProtocol {
    fn to_bytes(&self) -> Vec<u8> {
        match self {
            Self::Command(c) => c.to_bytes(),
            Self::PrintData(p) => p.to_bytes(),
            Self::Response(r) => r.to_bytes(),
        }
    }
}

#[derive(Debug)]
pub struct PrinterCutConfig {
    pub halfcut: bool,
    pub autocut: bool,
}
impl ToBytes for PrinterCutConfig {
    fn to_bytes(&self) -> Vec<u8> {
        let mut payload = match (self.halfcut, self.autocut) {
            (true, true) => vec![2, 2, 1, 1],
            (false, true) => vec![1, 1, 1, 1],
            (false, false) => vec![0, 0, 0, 0],
            (_, _) => unimplemented!(),
        };
        payload.insert(0, 0x43);
        payload
    }
}

#[derive(Debug)]
pub enum PrinterCommand {
    // 0x4c
    TapeLength(u32),
    // 0x44
    PrintDensity(u8),
    // 0x43
    CutConfig(PrinterCutConfig),
    Unknown(Vec<u8>),
}

impl ToBytes for PrinterCommand {
    fn to_bytes(&self) -> Vec<u8> {
        // 1b 7b [len] [payload] [csum] 7d
        let payload: Vec<u8> = match self {
            Self::TapeLength(t) => {
                let mut tmp = t.to_le_bytes().to_vec();
                tmp.insert(0, 0x4c);
                tmp
            }
            Self::PrintDensity(p) => vec![0x44, *p],
            Self::CutConfig(c) => c.to_bytes(),
            Self::Unknown(u) => u.clone(),
        };
        let csum: u8 = payload.iter().map(|x| *x as u16).sum::<u16>() as u8;
        let mut bytes = vec![0x1b, 0x7b, payload.len() as u8 + 2];
        bytes.extend_from_slice(&payload);
        bytes.push(csum);
        bytes.push(0x7d);
        bytes
    }
}

#[derive(Debug)]
pub struct PrinterPrintData {
    lines: Vec<PrinterPrintDataLine>,
}
impl ToBytes for PrinterPrintData {
    fn to_bytes(&self) -> Vec<u8> {
        let mut bytes: Vec<u8> = self.lines.iter().map(|x| x.to_bytes()).flatten().collect();
        // teminal byte
        bytes.push(0x0c);
        bytes
    }
}

impl From<&TapeDisplay> for PrinterPrintData {
    fn from(value: &TapeDisplay) -> Self {
        let mut lines: Vec<PrinterPrintDataLine> = Vec::new();
        let row_bytes = (value.height + 7) / 8;
        for y in 0..value.width {
            let mut data: Vec<u8> = Vec::new();
            for xb in 0..row_bytes {
                let mut chunk = 0x00;
                for dx in 0..8 {
                    let x = xb * 8 + (7 - dx);
                    if value.get_pixel(value.width - 1 - y, x) {
                        chunk |= 1 << dx
                    }
                }
                data.push(chunk);
            }
            lines.push(PrinterPrintDataLine {
                bit_length: value.height as u16,
                data,
            });
        }
        PrinterPrintData { lines }
    }
}

#[derive(Debug)]
pub struct PrinterPrintDataLine {
    bit_length: u16,
    data: Vec<u8>,
}
impl ToBytes for PrinterPrintDataLine {
    fn to_bytes(&self) -> Vec<u8> {
        // 1b 2e 0 0 0 1 [bits1] [bits2] [img_data]
        let mut bytes: Vec<u8> = vec![0x1b, 0x2e, 0x00, 0x00, 0x00, 0x01];
        bytes.extend_from_slice(&self.bit_length.to_le_bytes());
        bytes.extend_from_slice(&self.data);
        bytes
    }
}

#[derive(Debug)]
pub struct PrinterResponse {
    data: Vec<u8>,
}
impl ToBytes for PrinterResponse {
    fn to_bytes(&self) -> Vec<u8> {
        todo!();
    }
}

pub fn parse_printer_packets(data: &[u8]) -> IResult<&[u8], Vec<PrinterProtocol>> {
    let (rest, protocols) = many0(alt((
        parse_printer_command,
        parse_printer_print_data,
        parse_printer_response,
    )))(data)?;
    Ok((rest, protocols))
}

fn parse_printer_command_tape_length(data: &[u8]) -> IResult<&[u8], PrinterCommand> {
    // 4c [tape length(u32)]
    let (rest, _) = tag(b"\x4c")(data)?;
    let (rest, length) = le_u32(rest)?;
    Ok((rest, PrinterCommand::TapeLength(length)))
}

fn parse_printer_command_density(data: &[u8]) -> IResult<&[u8], PrinterCommand> {
    // 44 [density(u8, min=3?, default=5, max=8?)]
    let (rest, _) = tag(b"\x44")(data)?;
    let (rest, density) = u8(rest)?;
    Ok((rest, PrinterCommand::PrintDensity(density)))
}

fn parse_printer_command_cut(data: &[u8]) -> IResult<&[u8], PrinterCommand> {
    // 43 [cut flags?]
    let (rest, _) = tag(b"\x43")(data)?;
    let (rest, option_bytes) = take(4u8)(rest)?;
    let (halfcut, autocut) = match option_bytes {
        &[2, 2, 1, 1] => (true, true),
        &[1, 1, 1, 1] => (false, true),
        _ => (false, false),
    };

    Ok((
        rest,
        PrinterCommand::CutConfig(PrinterCutConfig { halfcut, autocut }),
    ))
}

fn parse_printer_command(data: &[u8]) -> IResult<&[u8], PrinterProtocol> {
    // 1b 7b [len] [payload] [csum] 7d
    let (rest, _) = tag(b"\x1b\x7b")(data)?;
    let (rest, len) = u8(rest)?;
    let (rest, payload) = take(len - 2)(rest)?;
    // todo: check csum
    let calcurated_csum = payload.iter().map(|x| *x as u16).sum::<u16>() as u8;
    let (rest, csum) = u8(rest)?;
    if calcurated_csum != csum {
        println!("checksum missmatch");
    }
    let (rest, _) = tag(b"\x7d")(rest)?;

    let payload = match alt((
        parse_printer_command_tape_length,
        parse_printer_command_density,
        parse_printer_command_cut,
    ))(payload)
    {
        Ok((_, p)) => p,
        _ => PrinterCommand::Unknown(payload.to_vec()),
    };
    // let payload = printerCommand::Unknown(payload.to_vec());

    Ok((rest, PrinterProtocol::Command(payload)))
}

fn parse_printer_print_data_single(data: &[u8]) -> IResult<&[u8], PrinterPrintDataLine> {
    // 1b 2e 0 0 0 1 [bits1] [bits2] [img_data]
    let (rest, _) = tag(b"\x1b\x2e")(data)?;
    let (rest, _) = tag(b"\x00\x00\x00\x01")(rest)?;
    let (rest, bits) = le_u16(rest)?;
    let bytes = (bits + 7) / 8;
    let (rest, payload) = take(bytes)(rest)?;

    Ok((
        rest,
        PrinterPrintDataLine {
            bit_length: bits,
            data: payload.to_vec(),
        },
    ))
}

fn parse_printer_print_data(data: &[u8]) -> IResult<&[u8], PrinterProtocol> {
    // 1b 2e 0 0 0 1 [bits1] [bits2] [img_data]
    // ...
    // 0c
    let (rest, lines) = many1(parse_printer_print_data_single)(data)?;
    let (rest, _) = tag(b"\x0c")(rest)?;

    Ok((rest, PrinterProtocol::PrintData(PrinterPrintData { lines })))
}

fn parse_printer_response(data: &[u8]) -> IResult<&[u8], PrinterProtocol> {
    // 40 42 44 43 20 53 54 32 0d 0a 50 00 [data] [csum(data)]
    let (rest, _header) = tag(b"\x40\x42\x44\x43\x20\x53\x54\x32\x0d\x0a\x50\x00")(data)?;
    let (rest, unknown) = u8(rest)?;
    let (rest, length) = u8(rest)?;
    let (rest, payload) = take(length - 1)(rest)?;
    // todo: check csum
    let calcurated_csum =
        (payload.iter().map(|x| *x as u16).sum::<u16>() + unknown as u16 + length as u16) as u8;
    let (rest, csum) = u8(rest)?;
    if calcurated_csum != csum {
        println!("checksum missmatch");
    }
    Ok((
        rest,
        PrinterProtocol::Response(PrinterResponse {
            data: payload.to_vec(),
        }),
    ))
}
