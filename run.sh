#!/bin/sh
cargo build --release
ext=$?

if [ $ext -ne 0 ]; then
    exit $ext
fi

export CARGO_TARGET_DIR=target

sudo setcap cap_net_admin=eip $CARGO_TARGET_DIR/release/mini_tcp

$CARGO_TARGET_DIR/release/mini_tcp &
pid=$!

sleep 1 #give some time to create the TUN device

echo "Setting up TUN interface..."
sudo ip addr add 192.168.0.1/24 dev tun0
sudo ip link set up dev tun0

trap "kill $pid" INT TERM

wait $pid