#!/bin/bash

# It is assumed that the directory structure is as follows:
# BASE_DIR/
#   airtel/
#     vilte/
#     vinet/
#   jio/
#     vilte/
#     vinet/
#   vi/
#     vilte/
#     vinet/
# <this script>
# 
# where each of the folders contain pcap files
# Also ensure that mpt_rs is installed before running this script

# Define the base directory
BASE_DIR=$(pwd)

# Create features directory structure if it doesn't exist
mkdir -p "${BASE_DIR}/features/airtel/" "${BASE_DIR}/features/jio" "${BASE_DIR}/features/vi"

# Define chunk lengths
chunk_lengths=(10 20 30 40 50 60)

# List of directories to process
declare -A directories=(
    ["airtel/vilte"]=0
    ["airtel/vinet"]=1
    ["jio/vilte"]=0
    ["jio/vinet"]=1
    ["vi/vilte"]=0
    ["vi/vinet"]=1
)


extract_features(){
    local chunk_length=$1
    local dir=$2
    local label=$3
    local full_path="${BASE_DIR}/${dir}"

    provider=$(echo $dir | cut -d'/' -f1)
    dir_name=$(echo $dir | tr '/' '_')

    # Create output directory for the current chunk length
    mkdir -p "${BASE_DIR}/features/${provider}/chunks_${chunk_length}s"
    # Create output directory for the current chunk length with PL
    mkdir -p "${BASE_DIR}/features/${provider}/chunks_${chunk_length}s_pl"

    # Set output file path
    output_file_pl="${BASE_DIR}/features/${provider}/chunks_${chunk_length}s_pl/${dir_name}.csv"
    output_file="${BASE_DIR}/features/${provider}/chunks_${chunk_length}s/${dir_name}.csv"

    mpt_rs -d "${full_path}" -c $chunk_length --summary "${output_file}" --pl "${output_file_pl}" -t ${label}

}

# Process each chunk length
for chunk_length in "${chunk_lengths[@]}"; do
    echo "Processing with chunk length: ${chunk_length} seconds"
    
    echo "Extracting features"
    for dir in "${!directories[@]}"; do
        extract_features ${chunk_length} ${dir} ${directories[${dir}]} &
    done


    echo "Completed processing for chunk length: ${chunk_length} seconds"
    echo ""
done

echo "Extraction completed. Feature files are stored in ${BASE_DIR}/features/"
