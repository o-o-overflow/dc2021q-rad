#! /bin/bash

sudo docker build -t dc2021q-rad-base -f Dockerfile.base .
sudo docker build -t dc2021q-rad-proxy -f Dockerfile.proxy .
sudo docker build -t dc2021q-rad -f Dockerfile .
sudo docker save dc2021q-rad-proxy | zstdmt -o scripts/rad_proxy.img.zst
sudo docker save dc2021q-rad | zstdmt -o scripts/rad.img.zst

