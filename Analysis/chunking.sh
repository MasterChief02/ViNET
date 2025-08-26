#!/bin/bash

# Define the output directory
output_dir="./chunks"

# Create the output directory if it doesn't exist
mkdir -p "$output_dir"

# Loop through each PCAP file in the current directory
for pcap_file in ./*.pcap; do
  # Check if any .pcap files exist
  if [ -e "$pcap_file" ]; then
    # Extract the base name of the file (without directory and extension)
    base_name=$(basename "$pcap_file" .pcap)
    
    # Split the PCAP file into 10-second chunks
    editcap -i 10 "$pcap_file" "$output_dir/${base_name}_chunk.pcap"
  else
    echo "No PCAP files found in the current directory."
    break
  fi
done

