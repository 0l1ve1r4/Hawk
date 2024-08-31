#!/bin/bash

# Build the project in release mode
cargo build --release

# Set network capabilities to the binary
sudo setcap cap_net_raw,cap_net_admin=eip target/release/Hawk

# Verify the capabilities
getcap target/release/Hawk

# Run the binary
exec ./target/release/Hawk
