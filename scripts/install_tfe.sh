#!/usr/bin/env bash

IPADDR=$(hostname -I | awk '{print $1}')
cd
mkdir install
cd install
aws s3 cp s3://aakulov-aws4-tfe-airgap . --recursive
tar -xf latest.tar.gz
sudo rm -rf /usr/share/keyrings/docker-archive-keyring.gpg
yes | sudo ./install.sh no-proxy private-address=$IPADDR public-address=$IPADDR
