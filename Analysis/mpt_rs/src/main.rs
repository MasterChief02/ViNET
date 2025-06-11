mod pcap_data;

use clap::Parser;
use std::io::Write;
use pcap_data::PacketData;

#[derive(Parser, Debug)]
#[command(name = "mpt_rs", about = "Rust Implementation of USENIX'18 Paper: Effective Detection of Multimedia Protocol Tunneling using Machine Learning")]
#[command(arg_required_else_help = true)]
struct Args {
    /// The path to the pcap file
    #[arg(short = 'f', long, required_unless_present = "pcap_dir")]
    pcap_file: Option<String>,

    /// The directory containing pcap files
    #[arg(short = 'd', long, required_unless_present = "pcap_file")]
    pcap_dir: Option<String>,

    /// Chunk size for the pcap file
    #[arg(short = 'c', long, default_value_t = 10)]
    chunk_size: u8,

    /// True label for the pcap file/directory
    #[arg(short = 't', long, required = true)]
    true_label: u8,

    /// The path to the output file for summary data
    #[arg(long = "summary")]
    output_file_summary: String,

    /// The path to the output file for packet length data
    #[arg(long = "pl")]
    output_file_pl: String,
}

fn main() {
    let args = Args::parse();
    if let Some(pcap_file) = args.pcap_file {
        let mut pcap = PacketData::new(pcap_file);
        let (summary_data, pl_data) = pcap.get_data(args.chunk_size).unwrap();


        let mut op_file_summary = std::fs::OpenOptions::new()
            .create(true)
            .truncate(true)
            .write(true)
            .open(&args.output_file_summary)
            .expect("Failed to open output file");
        op_file_summary.write(format!("{}\n", PacketData::get_header()).as_bytes()).expect("Failed to write header to output file");

        let mut op_file_pl = std::fs::OpenOptions::new()
            .create(true)
            .truncate(true)
            .write(true)
            .open(&args.output_file_pl)
            .expect("Failed to open output file");
        op_file_pl.write(format!("{}\n", PacketData::get_header_pl()).as_bytes()).expect("Failed to write header to output file");

        let datetime_str = pcap.get_datetime();
        for row in summary_data{
            let mut row_data = row.iter().map(|x| x.to_string()).collect::<Vec<String>>().join(",");
            row_data.push_str(&format!(",{},{}", datetime_str, args.true_label));
            op_file_summary.write(format!("{}\n", row_data).as_bytes()).expect("Failed to write data to output file");
        }

        for row in pl_data{
            let mut row_data = row.iter().map(|x| x.to_string()).collect::<Vec<String>>().join(",");
            row_data.push_str(&format!(",{},{}", datetime_str, args.true_label));
            op_file_pl.write(format!("{}\n", row_data).as_bytes()).expect("Failed to write data to output file");
        }

    }

    if let Some(pcap_dir) = args.pcap_dir {
        let mut op_file_summary = std::fs::OpenOptions::new()
            .create(true)
            .truncate(true)
            .write(true)
            .open(&args.output_file_summary)
            .expect("Failed to open output file");

        let mut op_file_pl = std::fs::OpenOptions::new()
            .create(true)
            .truncate(true)
            .write(true)
            .open(&args.output_file_pl)
            .expect("Failed to open output file");

        op_file_summary.write(format!("{}\n", PacketData::get_header()).as_bytes()).expect("Failed to write header to output file");
        op_file_pl.write(format!("{}\n", PacketData::get_header_pl()).as_bytes()).expect("Failed to write header to output file");

        for entry in std::fs::read_dir(pcap_dir).unwrap() {
            let entry = entry.unwrap();
            if entry.path().extension().unwrap_or_default() == "pcap" {
                let mut pcap = PacketData::new(entry.path().to_str().unwrap().to_string());
                let (summary_data, pl_data) = pcap.get_data(args.chunk_size).unwrap();
                let datetime_str = pcap.get_datetime();

                for row in summary_data{
                    let mut row_data = row.iter().map(|x| x.to_string()).collect::<Vec<String>>().join(",");
                    row_data.push_str(&format!(",{},{}", datetime_str, args.true_label));
                    op_file_summary.write(format!("{}\n", row_data).as_bytes()).expect("Failed to write data to output file");
                }

                for row in pl_data{
                    let mut row_data = row.iter().map(|x| x.to_string()).collect::<Vec<String>>().join(",");
                    row_data.push_str(&format!(",{},{}", datetime_str, args.true_label));
                    op_file_pl.write(format!("{}\n", row_data).as_bytes()).expect("Failed to write data to output file");
                }

            }
        }
    }
}
