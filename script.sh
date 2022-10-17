#!/bin/bash


cp build/cargo_target/x86_64-unknown-linux-musl/debug/firecracker .

rm -f /tmp/firecracker.socket

./firecracker --api-sock /tmp/firecracker.socket --config-file config_vm --log-path $(pwd)/file.txt --level Debug 2> file.txt
