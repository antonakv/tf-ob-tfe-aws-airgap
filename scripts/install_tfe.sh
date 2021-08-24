#!/usr/bin/env bash

IPADDR=$(hostname -I | awk '{print $1}')
mkdir install
cd install
aws s3 cp s3://aakulov-aws4-tfe-airgap . --recursive
tar -xf latest.tar.gz
sudo ./scripts/install.sh no-proxy private-address=$IPADDR public-address=$IPADDR
