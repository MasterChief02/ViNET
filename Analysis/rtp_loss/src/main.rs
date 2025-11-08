mod pcap_data;

use std::io::Write;

use clap::Parser;
use pcap_data::PacketData;
use regex::Regex;
use indicatif::ProgressBar;
use chrono::NaiveDateTime;

#[derive(Parser, Debug)]
#[command(
    name = "rtp_loss",
    about = "Rust library to compute RTP packet loss rates from pcap files"
)]
#[command(arg_required_else_help = true)]
struct Args {
    /// The path to alice pcap directory
    #[arg(long = "alice", required = true)]
    alice_dir: String,

    /// The path to bob pcap directory
    #[arg(long = "bob", required = true)]
    bob_dir: String,

    /// The path to the output file for summary data
    #[arg(short = 'o', long = "output", required = true)]
    output_file: String,
}

fn find_datetime_from_filename(file_path: &str) -> String {
    let pattern = r"(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d+)";
    let fmt = "%Y-%m-%dT%H:%M:%S%.6f";

    let re = Regex::new(pattern).map_err(|e| e.to_string()).unwrap();
    let file_name = std::path::Path::new(file_path).file_name().unwrap().to_str().unwrap();
    let datetime_str = re.captures(file_name).unwrap().get(0).unwrap().as_str();
    let datetime = NaiveDateTime::parse_from_str(datetime_str, fmt).unwrap();

    // truncate datetime to only minute precision
    datetime.format("%Y-%m-%dT%H:%M").to_string()
}

struct PcapFileInfo {
    file_path: String,
    datetime_hour: String,
}

fn main() {
    let args = Args::parse();

    let mut alice_files: Vec<PcapFileInfo> = Vec::new();
    let mut bob_files: Vec<PcapFileInfo> = Vec::new();

    for entry in std::fs::read_dir(args.alice_dir).unwrap() {
        let entry = entry.unwrap();
        if entry.path().extension().unwrap_or_default() == "pcap" {
            alice_files.push(PcapFileInfo {
                file_path: entry.path().to_string_lossy().to_string(),
                datetime_hour: find_datetime_from_filename(&entry.path().to_string_lossy()),
            });
        }
    }

    for entry in std::fs::read_dir(args.bob_dir).unwrap() {
        let entry = entry.unwrap();
        if entry.path().extension().unwrap_or_default() == "pcap" {
            bob_files.push(PcapFileInfo {
                file_path: entry.path().to_string_lossy().to_string(),
                datetime_hour: find_datetime_from_filename(&entry.path().to_string_lossy()),
            });
        }
    }

    
    let mut op_file = std::fs::OpenOptions::new()
            .create(true)
            .truncate(true)
            .write(true)
            .open(&args.output_file)
            .expect("Failed to open output file");

    op_file.write_all(b"timestamp,alice_packet_drop,bob_packet_drop_rate\n").unwrap();

    // Sort both vectors by datetime_hour
    alice_files.sort_by(|a, b| a.datetime_hour.cmp(&b.datetime_hour));
    bob_files.sort_by(|a, b| a.datetime_hour.cmp(&b.datetime_hour));

    let total_pairs = std::cmp::min(alice_files.len(), bob_files.len()) as u64;
    let pb = ProgressBar::new(total_pairs);

    for (alice_file, bob_file) in alice_files.iter().zip(bob_files.iter()) {
        if alice_file.datetime_hour != bob_file.datetime_hour {
            eprintln!("Warning: Mismatched datetime hours between alice and bob files: {} vs {}", alice_file.file_path, bob_file.file_path);
            pb.inc(1);
            continue;
        }
        let mut packet_data = PacketData::new(&alice_file.file_path, &bob_file.file_path);
        let (alice_drop_rate, bob_drop_rate) = packet_data.get_packet_drop_rate();

        let line = format!("{},{:.10},{:.10}\n", alice_file.datetime_hour, alice_drop_rate, bob_drop_rate);
        op_file.write_all(line.as_bytes()).unwrap();

        pb.inc(1);
    }

    pb.finish_with_message("processed files");
}
