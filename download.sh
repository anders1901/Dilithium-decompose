#!/bin/bash

# URL of the zip file
url="https://www.dropbox.com/scl/fo/8tqg64ze5zfr77pn8rgp8/h?dl=0&rlkey=h8vvmmyfr5jgxidty9n0pfkpo&dl=1"

# Directory to save the downloaded zip file
download_dir="download"

# Directory to unzip the dataset
unzip_dir="template/dataset"

# Ensure the download directory exists
mkdir -p "$download_dir"

# Download the zip file
echo "Downloading dataset.zip..."
curl -L -o "$download_dir/dataset.zip" "$url"

# Check if the download was successful
if [ $? -eq 0 ]; then
    echo "Download successful!"

    # Ensure the unzip directory exists
    mkdir -p "$unzip_dir"

    # Unzip the dataset.zip file
    echo "Unzipping dataset.zip..."
    unzip -q "$download_dir/dataset.zip" -d "$unzip_dir"

    if [ $? -eq 0 ]; then
        echo "Unzip successful! Dataset is now available in $unzip_dir"
    else
        echo "Unzip failed."
    fi
else
    echo "Download failed."
fi
