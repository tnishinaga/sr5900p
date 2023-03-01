#![feature(new_uninit)]
#![feature(slice_take)]
#![feature(exclusive_range_pattern)]

use anyhow::Result;
use argh::FromArgs;
use sr5900p::{
    analyzer::{analyze_btspp_data, analyze_tcp_data},
    print::{do_print, PrintArgs},
};
use std::fs;

#[derive(FromArgs, PartialEq, Debug)]
/// Analyze the packet captures
#[argh(subcommand, name = "analyze")]
struct AnalyzeArgs {
    #[argh(subcommand)]
    nested: AnalyzeSubCommand,
}

#[derive(FromArgs, PartialEq, Debug)]
/// Select Tcp or BtSpp
#[argh(subcommand)]
enum AnalyzeSubCommand {
    Tcp(TcpArgs),
    BtSpp(BtSppArgs),
}

#[derive(FromArgs, PartialEq, Debug)]
/// Analyze the tcp packet captures
#[argh(subcommand, name = "tcp")]
struct TcpArgs {
    /// the raw dump of the TCP stream while printing
    #[argh(option)]
    data: String,
}

#[derive(FromArgs, PartialEq, Debug)]
/// Analyze the bluetooth spp packet captures
#[argh(subcommand, name = "btspp")]
struct BtSppArgs {
    /// the btsnoop log while printing
    #[argh(option)]
    log: String,
    /// device's bluetooth address
    #[argh(option)]
    address: String,
}

fn do_analyze_tcp(dump_file: &str) -> Result<()> {
    let data = fs::read(dump_file)?;
    analyze_tcp_data(&data)
}

#[derive(FromArgs, PartialEq, Debug)]
#[argh(subcommand)]
enum ArgsSubCommand {
    Analyze(AnalyzeArgs),
    Print(PrintArgs),
}
#[derive(Debug, FromArgs)]
/// Reach new heights.
struct Args {
    #[argh(subcommand)]
    nested: ArgsSubCommand,
}

fn main() -> Result<()> {
    let args: Args = argh::from_env();
    println!("{:?}", args);
    match args.nested {
        ArgsSubCommand::Analyze(args) => match args.nested {
            AnalyzeSubCommand::BtSpp(spp) => analyze_btspp_data(&spp.log, &spp.address),
            AnalyzeSubCommand::Tcp(tcp) => do_analyze_tcp(&tcp.data),
        },
        ArgsSubCommand::Print(args) => do_print(&args),
    }
}
