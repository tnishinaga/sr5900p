use crate::analyzer::analyze_tcp_data;
use crate::display::TapeDisplay;
use crate::protocol::notify_data_stream;
use crate::protocol::StartPrintRequest;
use crate::protocol::StatusRequest;
use crate::protocol::StopPrintRequest;
use crate::PrinterStatus;
use crate::TapeKind;
use anyhow::anyhow;
use anyhow::Context;
use anyhow::Result;
use argh::FromArgs;
use barcoders::sym::code39::Code39;
use embedded_graphics::geometry::Dimensions;
use embedded_graphics::geometry::Point;
use embedded_graphics::mono_font::ascii::FONT_10X20;
use embedded_graphics::mono_font::MonoTextStyle;
use embedded_graphics::pixelcolor::BinaryColor;
use embedded_graphics::text::Alignment;
use embedded_graphics::text::Text;
use embedded_graphics::Drawable;
use std::fs;
use std::io::prelude::Write;
use std::net::TcpStream;
use std::net::UdpSocket;
use std::num::Wrapping;
use std::thread;
use std::time;

#[derive(FromArgs, PartialEq, Debug)]
/// Print something
#[argh(subcommand, name = "print")]
pub struct PrintArgs {
    /// label data generation test
    #[argh(switch)]
    gen_test: bool,
    /// do not print (just generate and analyze)
    #[argh(switch)]
    dry_run: bool,
    /// the raw dump of the TCP stream while printing
    #[argh(option)]
    tcp_data: Option<String>,
    /// an IPv4 address for the printer
    #[argh(option)]
    printer: String,
}
fn print_tcp_data(device_ip: &str, data: &[u8]) -> Result<()> {
    let socket = UdpSocket::bind("0.0.0.0:0").context("failed to bind")?;
    let info = StatusRequest::send(&socket, device_ip)?;
    println!("{:?}", info);
    if let PrinterStatus::SomeTape(t) = info {
        println!("Tape is {:?}, start printing...", t);
    } else {
        println!("Unexpected state. Aborting...");
        std::process::exit(1);
    }
    StartPrintRequest::send(&socket, device_ip)?;
    thread::sleep(time::Duration::from_millis(500));
    let mut stream = TcpStream::connect(device_ip.to_string() + ":9100")?;
    thread::sleep(time::Duration::from_millis(500));
    notify_data_stream(&socket, device_ip)?;
    thread::sleep(time::Duration::from_millis(500));
    stream.write(&data)?;

    println!("Print data is sent. Waiting...");
    loop {
        thread::sleep(time::Duration::from_millis(500));
        let info = StatusRequest::send(&socket, device_ip)?;
        println!("{:?}", info);
        if let PrinterStatus::Printing = info {
            continue;
        }
        break;
    }

    StopPrintRequest::send(&socket, device_ip)?;

    Ok(())
}
pub fn do_print(args: PrintArgs) -> Result<()> {
    let device_ip = &args.printer;
    match (args.gen_test, args.tcp_data) {
        (false, Some(tcp_data)) => {
            let label_data = fs::read(tcp_data).context("Failed to read TCP data")?;
            print_tcp_data(device_ip, &label_data)
        }
        (true, None) => {
            let socket = UdpSocket::bind("0.0.0.0:0").context("failed to bind")?;
            let info = StatusRequest::send(&socket, device_ip)?;
            let tape_width_px = if let PrinterStatus::SomeTape(t) = info {
                println!("Tape is {:?}", t);
                match t {
                    TapeKind::W9 => 9 * 360 * 10 / 254,
                    TapeKind::W12 => 12 * 360 * 10 / 254,
                    TapeKind::W18 => 18 * 360 * 10 / 254,
                    TapeKind::W24 => 24 * 360 * 10 / 254,
                    _ => {
                        return Err(anyhow!(
                            "Failed to determine tape width. status: {:?}",
                            info
                        ))
                    }
                }
            } else {
                return Err(anyhow!(
                    "Failed to determine tape width. status: {:?}",
                    info
                ));
            };
            let tape_width_px = (tape_width_px + 7) / 8 * 8;

            let text = "a0:ce:c8:d4:6b:39".to_uppercase().replace(":", "");
            println!("{:?}", text);
            let barcode = Code39::new(text).context("Failed to generate a barcode")?;
            let encoded: Vec<u8> = barcode.encode();
            println!("{:?}", encoded);

            let barcode_min_px_size = 4;
            let barcode_padding_px = 64;
            let tape_len_px = barcode_min_px_size * encoded.len() + barcode_padding_px * 2;

            let mut td = TapeDisplay::new(tape_len_px / 4, tape_width_px / 4);
            let text = "embedded-graphics";
            let character_style = MonoTextStyle::new(&FONT_10X20, BinaryColor::On);
            Text::with_alignment(
                text,
                td.bounding_box().center() + Point::new(0, 5),
                character_style,
                Alignment::Center,
            )
            .draw(&mut td)?;

            let row_bytes = (tape_width_px + 7) / 8;

            let mut tcp_data: Vec<u8> = Vec::new();
            tcp_data.append(&mut vec![27, 123, 3, 64, 64, 125]);
            tcp_data.append(&mut vec![27, 123, 7, 123, 0, 0, 83, 84, 34, 125]);
            tcp_data.append(&mut vec![27, 123, 7, 67, 2, 2, 1, 1, 73, 125]); // half-cut?
            tcp_data.append(&mut vec![27, 123, 4, 68, 5, 73, 125]);
            tcp_data.append(&mut vec![27, 123, 3, 71, 71, 125]);

            let mut tape_len_bytes = (tape_len_px as u32).to_le_bytes().to_vec();
            let mut cmd_bytes = vec![76];
            cmd_bytes.append(&mut tape_len_bytes);
            let csum = cmd_bytes
                .iter()
                .map(|v| Wrapping(*v))
                .sum::<Wrapping<u8>>()
                .0;
            cmd_bytes.push(csum);
            cmd_bytes.push(0x7d);
            tcp_data.append(&mut vec![0x1b, 0x7b, cmd_bytes.len() as u8]);
            tcp_data.append(&mut cmd_bytes);

            tcp_data.append(&mut vec![27, 123, 5, 84, 42, 0, 126, 125]);
            tcp_data.append(&mut vec![27, 123, 4, 72, 5, 77, 125]);
            tcp_data.append(&mut vec![27, 123, 4, 115, 0, 115, 125]);

            for y in 0..tape_len_px {
                tcp_data.append(&mut vec![0x1b, 0x2e, 0, 0, 0, 1]);
                tcp_data.append(&mut (tape_width_px as u16).to_le_bytes().to_vec());
                for xb in 0..row_bytes {
                    let mut chunk = 0x00;
                    for dx in 0..8 {
                        let x = xb * 8 + (7 - dx);

                        if td.framebuffer[x / 4][(tape_len_px - 1 - y) / 4] {
                            chunk = chunk | (1 << dx)
                        }
                    }
                    tcp_data.push(chunk);
                }
            }
            tcp_data.push(0x0c); // data end
            tcp_data.append(&mut vec![27, 123, 3, 64, 64, 125]);

            analyze_tcp_data(&tcp_data)?;
            if !args.dry_run {
                print_tcp_data(device_ip, &tcp_data)
            } else {
                println!("--dry-run is specified, skipping printing phase");
                Ok(())
            }
        }
        (_, _) => Err(anyhow!(
            "Please specify one of following options: --tcp-data, --gen-test"
        )),
    }
}