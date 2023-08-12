#!/bin/bash

# Source and destination directories
source_dir="additional_materials/c_materials/"
destination_dir="dilithium/ref/"

# Check if the source directory exists
if [ ! -d "$source_dir" ]; then
    echo "Source directory not found: $source_dir"
    exit 1
fi

# Check if the destination directory exists, create it if not
if [ ! -d "$destination_dir" ]; then
    mkdir -p "$destination_dir"
fi

# Copy files from source to destination
cp -r "$source_dir"* "$destination_dir"

echo "Files copied successfully from $source_dir to $destination_dir"
