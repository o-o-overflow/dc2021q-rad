#! /bin/bash

sudo docker run -d --name rad_proxy \
    --replace \
    --restart no \
    --network host \
    -p 1337:1337/tcp \
    -e RUST_LOG=debug -e RUST_BACKTRACE=1 \
    dc2021q-rad-proxy proxy -c /proxy.toml
sudo docker run -d --name rad_node \
    --replace \
    --restart no \
    --network host \
    --cgroupns host \
    -p 1338:1338/tcp \
    -e RUST_LOG=debug -e RUST_BACKTRACE=1 \
    --privileged \
    --ulimit host \
    -v /var/run/docker.sock:/var/run/docker.sock:rw \
    dc2021q-rad-proxy node -c /node.toml
