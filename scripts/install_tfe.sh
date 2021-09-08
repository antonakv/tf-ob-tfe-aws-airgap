#!/usr/bin/env bash

IPADDR=$(hostname -I | awk '{print $1}')
mkdir -p /home/ubuntu/install
cd /home/ubuntu/install
aws s3 cp s3://aakulov-aws4-tfe-airgap . --recursive
tar -xf latest.tar.gz
aws s3 cp s3://aakulov-aws4-tfe-airgap/Terraform\ Enterprise\ -\ 557.airgap tfe557.airgap
sudo rm Terraform\ Enterprise\ -\ 557.airgap
sudo rm -rf /usr/share/keyrings/docker-archive-keyring.gpg
yes | sudo ./install.sh no-proxy private-address=$IPADDR public-address=$IPADDR
