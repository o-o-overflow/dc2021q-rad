#! /bin/bash

rm -f scripts/*.img.zst
sudo docker build -t dc2021q-rad-base -f Dockerfile.base . || exit 1
sudo docker build -t dc2021q-rad-proxy -f Dockerfile.proxy . || exit 1
sudo docker build -t dc2021q-rad -f Dockerfile . || exit 1
sudo docker save dc2021q-rad-proxy | zstdmt -o scripts/rad_proxy.img.zst || exit 1
sudo docker save dc2021q-rad | zstdmt -o scripts/rad.img.zst || exit 1
#sudo docker create --name rad_artifacts dc2021q-rad-base /bin/sh || exit 1
#sudo docker cp rad_artifacts:/src/target/release/rad_fw public/rad_fw || exit 1
#sudo docker cp rad_artifacts:/src/target/release/rad_client public/rad_client || exit 1
#sudo docker rm -f rad_artifacts

