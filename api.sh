#!/bin/sh

curl --unix-socket /tmp/firecracker.socket -i \
    -X PATCH "http://localhost/virtio-mem/memory_dev_1/" \
    -d '{ "requested_size_kib": 8388608 }'
