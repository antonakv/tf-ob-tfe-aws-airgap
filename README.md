# tf-ob-tfe-aws-airgap

This manual is dedicated to install TFE on Prod version External Services ( S3 + DB ) with Valid Certificate - AWS install with airgap.

## Requirements

- Hashicorp terraform recent version installed
[Terraform installation manual](https://learn.hashicorp.com/tutorials/terraform/install-cli)

- git installed
[Git installation manual](https://git-scm.com/download/mac)

- Amazon AWS account credentials saved in .aws/credentials file
[Configuration and credential file settings](https://docs.aws.amazon.com/cli/latest/userguide/cli-configure-files.html)

- Configured AWS Route53 DNS zone for domain `myname.hashicorp-success.com`
[Amazon Route53: Working with public hosted zones](https://docs.aws.amazon.com/Route53/latest/DeveloperGuide/AboutHZWorkingWith.html)

- Created Amazon EC2 key pair for Linux instance
[Create a key pair using Amazon EC2](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ec2-key-pairs.html#having-ec2-create-your-key-pair)

## Preparation 

- Clone git repository

```bash
git clone https://github.com/antonakv/tf-ob-tfe-aws-airgap.git
```

Expected command output looks like this:

```bash
Cloning into 'tf-ob-tfe-aws-airgap'...
remote: Enumerating objects: 12, done.
remote: Counting objects: 100% (12/12), done.
remote: Compressing objects: 100% (12/12), done.
remote: Total 12 (delta 1), reused 3 (delta 0), pack-reused 0
Receiving objects: 100% (12/12), done.
Resolving deltas: 100% (1/1), done.
```

- Change folder to tf-ob-tfe-aws-airgap

```bash
cd tf-ob-tfe-aws-airgap
```

- Create file testing.tfvars with following contents

```
key_name      = "NameOfYourEC2Keypair"
ami           = "ami-01b7850ca14523f9a"
instance_type = "t2.medium"
region        = "eu-central-1"
cidr_vpc      = "10.5.0.0/16"
cidr_subnet1  = "10.5.1.0/24"
cidr_subnet2  = "10.5.2.0/24"
cidr_subnet3  = "10.5.3.0/24"
cidr_subnet4  = "10.5.4.0/24"
db_password   = "PutYourValueHure"
enc_password  = "PutYourValueHure"
tfe_hostname  = "tfe4.myname.hashicorp-success.com"
```

- Change folder to `pre-req`

Follow `pre-req/README.md` manual to prepare assets on Amazon S3 required for the installation

## Run terraform code

- In the same folder you were before, run 

```bash
terraform init
```

Sample result

```
$ terraform init   

Initializing the backend...

Initializing provider plugins...
- Reusing previous version of hashicorp/aws from the dependency lock file
- Reusing previous version of hashicorp/tls from the dependency lock file
- Reusing previous version of hashicorp/template from the dependency lock file
- Installing hashicorp/aws v3.52.0...
- Installed hashicorp/aws v3.52.0 (signed by HashiCorp)
- Installing hashicorp/tls v3.1.0...
- Installed hashicorp/tls v3.1.0 (signed by HashiCorp)
- Installing hashicorp/template v2.2.0...
- Installed hashicorp/template v2.2.0 (signed by HashiCorp)

Terraform has been successfully initialized!

You may now begin working with Terraform. Try running "terraform plan" to see
any changes that are required for your infrastructure. All Terraform commands
should now work.

If you ever set or change modules or backend configuration for Terraform,
rerun this command to reinitialize your working directory. If you forget, other
commands will detect it and remind you to do so if necessary.
```

- Execute `terraform apply`

```
$ terraform apply

Terraform used the selected providers to generate the following execution plan. Resource actions are indicated with the following symbols:
  + create
 <= read (data resources)

Terraform will perform the following actions:

  # data.template_cloudinit_config.aws4_cloudinit will be read during apply
  # (config refers to values not yet known)
 <= data "template_cloudinit_config" "aws4_cloudinit"  {
      + base64_encode = true
      + gzip          = true
      + id            = (known after apply)
      + rendered      = (known after apply)

      + part {
          + content      = (known after apply)
          + content_type = "text/x-shellscript"
          + filename     = "install_tfe.sh"
        }
    }

  # data.template_file.install_tfe_sh will be read during apply
  # (config refers to values not yet known)
 <= data "template_file" "install_tfe_sh"  {
      + id       = (known after apply)
      + rendered = (known after apply)
      + template = <<-EOT
            #!/usr/bin/env bash
            mkdir -p /home/ubuntu/install
            echo "
            {
                \"aws_access_key_id\": {},
                \"aws_instance_profile\": {
                    \"value\": \"1\"
                },
                \"aws_secret_access_key\": {},
                \"azure_account_key\": {},
                \"azure_account_name\": {},
                \"azure_container\": {},
                \"azure_endpoint\": {},
                \"backup_token\": {
                    \"value\": \"3e69c0572c1eddf7f232cf60f6b8634194bf40d09aa9535c78430e64df407ec4\"
                },
                \"ca_certs\": {},
                \"capacity_concurrency\": {
                    \"value\": \"10\"
                },
                \"capacity_memory\": {
                    \"value\": \"512\"
                },
                \"custom_image_tag\": {
                    \"value\": \"hashicorp/build-worker:now\"
                },
                \"disk_path\": {},
                \"enable_active_active\": {
                    \"value\": \"0\"
                },
                \"enable_metrics_collection\": {
                    \"value\": \"1\"
                },
                \"enc_password\": {
                    \"value\": \"${enc_password}\"
                },
                \"extern_vault_addr\": {},
                \"extern_vault_enable\": {
                    \"value\": \"0\"
                },
                \"extern_vault_path\": {},
                \"extern_vault_propagate\": {},
                \"extern_vault_role_id\": {},
                \"extern_vault_secret_id\": {},
                \"extern_vault_token_renew\": {},
                \"extra_no_proxy\": {},
                \"force_tls\": {
                    \"value\": \"0\"
                },
                \"gcs_bucket\": {},
                \"gcs_credentials\": {
                    \"value\": \"{}\"
                },
                \"gcs_project\": {},
                \"hairpin_addressing\": {
                    \"value\": \"0\"
                },
                \"hostname\": {
                    \"value\": \"${hostname}\"
                },
                \"iact_subnet_list\": {},
                \"iact_subnet_time_limit\": {
                    \"value\": \"60\"
                },
                \"installation_type\": {
                    \"value\": \"production\"
                },
                \"pg_dbname\": {
                    \"value\": \"mydbtfe\"
                },
                \"pg_extra_params\": {
                    \"value\": \"sslmode=disable\"
                },
                \"pg_netloc\": {
                    \"value\": \"${pgsqlhostname}\"
                },
                \"pg_password\": {
                    \"value\": \"${pgsqlpassword}\"
                },
                \"pg_user\": {
                    \"value\": \"${pguser}\"
                },
                \"placement\": {
                    \"value\": \"placement_s3\"
                },
                \"production_type\": {
                    \"value\": \"external\"
                },
                \"redis_host\": {},
                \"redis_pass\": {
                    \"value\": \"NGVITSiZJKkmtC9ed1XWjScsVZMnXJx5\"
                },
                \"redis_port\": {},
                \"redis_use_password_auth\": {},
                \"redis_use_tls\": {},
                \"restrict_worker_metadata_access\": {
                    \"value\": \"0\"
                },
                \"s3_bucket\": {
                    \"value\": \"${s3bucket}\"
                },
                \"s3_endpoint\": {},
                \"s3_region\": {
                    \"value\": \"${s3region}\"
                },
                \"s3_sse\": {},
                \"s3_sse_kms_key_id\": {},
                \"tbw_image\": {
                    \"value\": \"default_image\"
                },
                \"tls_ciphers\": {},
                \"tls_vers\": {
                    \"value\": \"tls_1_2_tls_1_3\"
                }
            }
            " > /home/ubuntu/install/settings.json
            
            echo "
            {
                \"DaemonAuthenticationType\":     \"password\",
                \"DaemonAuthenticationPassword\": \"Password1#\",
                \"TlsBootstrapType\":             \"server-path\",
                \"TlsBootstrapHostname\":         \"${hostname}\",
                \"TlsBootstrapCert\":             \"/home/ubuntu/install/server.crt\",
                \"TlsBootstrapKey\":              \"/home/ubuntu/install/server.key\",
                \"BypassPreflightChecks\":        true,
                \"ImportSettingsFrom\":           \"/home/ubuntu/install/settings.json\",
                \"LicenseFileLocation\":          \"/home/ubuntu/install/license.rli\",
                \"LicenseBootstrapAirgapPackagePath\": \"/home/ubuntu/install/tfe-557.airgap\"
            }" > /home/ubuntu/install/replicated.conf
            echo "${cert_pem}" > /home/ubuntu/install/server.crt
            echo "${key_pem}" > /home/ubuntu/install/server.key
            IPADDR=$(hostname -I | awk '{print $1}')
            echo "#!/usr/bin/env bash
            chmod 600 /home/ubuntu/install/server.key
            cd /home/ubuntu/install
            aws s3 cp s3://aakulov-aws4-tfe-airgap . --recursive
            tar -xf latest.tar.gz
            sudo rm -rf /usr/share/keyrings/docker-archive-keyring.gpg
            cp /home/ubuntu/install/replicated.conf /etc/replicated.conf
            cp /home/ubuntu/install/replicated.conf /root/replicated.conf
            chown -R ubuntu: /home/ubuntu/install
            yes | sudo ./install.sh airgap no-proxy private-address=$IPADDR public-address=$IPADDR" > /home/ubuntu/install/install_tfe.sh
            
            chmod +x /home/ubuntu/install/install_tfe.sh
            
            sh /home/ubuntu/install/install_tfe.sh &> /home/ubuntu/install/install_tfe.log
        EOT
      + vars     = {
          + "cert_pem"      = (known after apply)
          + "enc_password"  = (sensitive)
          + "hostname"      = "tfe4.anton.hashicorp-success.com"
          + "key_pem"       = (sensitive)
          + "pgsqlhostname" = (known after apply)
          + "pgsqlpassword" = (sensitive)
          + "pguser"        = "postgres"
          + "s3bucket"      = "aakulov-aws4-tfe-data"
          + "s3region"      = "eu-central-1"
        }
    }

  # aws_db_instance.aws4 will be created
  + resource "aws_db_instance" "aws4" {
      + address                               = (known after apply)
      + allocated_storage                     = 20
      + apply_immediately                     = (known after apply)
      + arn                                   = (known after apply)
      + auto_minor_version_upgrade            = true
      + availability_zone                     = (known after apply)
      + backup_retention_period               = (known after apply)
      + backup_window                         = (known after apply)
      + ca_cert_identifier                    = (known after apply)
      + character_set_name                    = (known after apply)
      + copy_tags_to_snapshot                 = false
      + db_subnet_group_name                  = "aakulov-aws4"
      + delete_automated_backups              = true
      + endpoint                              = (known after apply)
      + engine                                = "postgres"
      + engine_version                        = "12.7"
      + hosted_zone_id                        = (known after apply)
      + id                                    = (known after apply)
      + identifier                            = (known after apply)
      + identifier_prefix                     = (known after apply)
      + instance_class                        = "db.t2.micro"
      + kms_key_id                            = (known after apply)
      + latest_restorable_time                = (known after apply)
      + license_model                         = (known after apply)
      + maintenance_window                    = (known after apply)
      + max_allocated_storage                 = 100
      + monitoring_interval                   = 0
      + monitoring_role_arn                   = (known after apply)
      + multi_az                              = (known after apply)
      + name                                  = "mydbtfe"
      + option_group_name                     = (known after apply)
      + parameter_group_name                  = (known after apply)
      + password                              = (sensitive value)
      + performance_insights_enabled          = false
      + performance_insights_kms_key_id       = (known after apply)
      + performance_insights_retention_period = (known after apply)
      + port                                  = (known after apply)
      + publicly_accessible                   = false
      + replicas                              = (known after apply)
      + resource_id                           = (known after apply)
      + skip_final_snapshot                   = true
      + snapshot_identifier                   = (known after apply)
      + status                                = (known after apply)
      + storage_type                          = (known after apply)
      + tags                                  = {
          + "Name" = "aakulov-aws4"
        }
      + tags_all                              = {
          + "Name" = "aakulov-aws4"
        }
      + timezone                              = (known after apply)
      + username                              = "postgres"
      + vpc_security_group_ids                = (known after apply)
    }

  # aws_db_subnet_group.aws4 will be created
  + resource "aws_db_subnet_group" "aws4" {
      + arn         = (known after apply)
      + description = "Managed by Terraform"
      + id          = (known after apply)
      + name        = "aakulov-aws4"
      + name_prefix = (known after apply)
      + subnet_ids  = (known after apply)
      + tags        = {
          + "Name" = "aakulov-aws4"
        }
      + tags_all    = {
          + "Name" = "aakulov-aws4"
        }
    }

  # aws_eip.aws4 will be created
  + resource "aws_eip" "aws4" {
      + allocation_id        = (known after apply)
      + association_id       = (known after apply)
      + carrier_ip           = (known after apply)
      + customer_owned_ip    = (known after apply)
      + domain               = (known after apply)
      + id                   = (known after apply)
      + instance             = (known after apply)
      + network_border_group = (known after apply)
      + network_interface    = (known after apply)
      + private_dns          = (known after apply)
      + private_ip           = (known after apply)
      + public_dns           = (known after apply)
      + public_ip            = (known after apply)
      + public_ipv4_pool     = (known after apply)
      + tags_all             = (known after apply)
      + vpc                  = true
    }

  # aws_iam_instance_profile.aakulov-aws4-ec2-s3 will be created
  + resource "aws_iam_instance_profile" "aakulov-aws4-ec2-s3" {
      + arn         = (known after apply)
      + create_date = (known after apply)
      + id          = (known after apply)
      + name        = "aakulov-aws4-ec2-s3"
      + path        = "/"
      + role        = "aakulov-aws4-iam-role-ec2-s3"
      + tags_all    = (known after apply)
      + unique_id   = (known after apply)
    }

  # aws_iam_role.aakulov-aws4-iam-role-ec2-s3 will be created
  + resource "aws_iam_role" "aakulov-aws4-iam-role-ec2-s3" {
      + arn                   = (known after apply)
      + assume_role_policy    = jsonencode(
            {
              + Statement = [
                  + {
                      + Action    = "sts:AssumeRole"
                      + Effect    = "Allow"
                      + Principal = {
                          + Service = "ec2.amazonaws.com"
                        }
                      + Sid       = ""
                    },
                ]
              + Version   = "2012-10-17"
            }
        )
      + create_date           = (known after apply)
      + force_detach_policies = false
      + id                    = (known after apply)
      + managed_policy_arns   = (known after apply)
      + max_session_duration  = 3600
      + name                  = "aakulov-aws4-iam-role-ec2-s3"
      + path                  = "/"
      + tags                  = {
          + "tag-key" = "aakulov-aws4-iam-role-ec2-s3"
        }
      + tags_all              = {
          + "tag-key" = "aakulov-aws4-iam-role-ec2-s3"
        }
      + unique_id             = (known after apply)

      + inline_policy {
          + name   = (known after apply)
          + policy = (known after apply)
        }
    }

  # aws_iam_role_policy.aakulov-aws4-ec2-s3 will be created
  + resource "aws_iam_role_policy" "aakulov-aws4-ec2-s3" {
      + id     = (known after apply)
      + name   = "aakulov-aws4-ec2-s3"
      + policy = (known after apply)
      + role   = (known after apply)
    }

  # aws_instance.aws4 will be created
  + resource "aws_instance" "aws4" {
      + ami                                  = "ami-01b7850ca14523f9a"
      + arn                                  = (known after apply)
      + associate_public_ip_address          = true
      + availability_zone                    = (known after apply)
      + cpu_core_count                       = (known after apply)
      + cpu_threads_per_core                 = (known after apply)
      + disable_api_termination              = (known after apply)
      + ebs_optimized                        = (known after apply)
      + get_password_data                    = false
      + host_id                              = (known after apply)
      + iam_instance_profile                 = (known after apply)
      + id                                   = (known after apply)
      + instance_initiated_shutdown_behavior = (known after apply)
      + instance_state                       = (known after apply)
      + instance_type                        = "t2.medium"
      + ipv6_address_count                   = (known after apply)
      + ipv6_addresses                       = (known after apply)
      + key_name                             = "aakulov"
      + monitoring                           = (known after apply)
      + outpost_arn                          = (known after apply)
      + password_data                        = (known after apply)
      + placement_group                      = (known after apply)
      + primary_network_interface_id         = (known after apply)
      + private_dns                          = (known after apply)
      + private_ip                           = (known after apply)
      + public_dns                           = (known after apply)
      + public_ip                            = (known after apply)
      + secondary_private_ips                = (known after apply)
      + security_groups                      = (known after apply)
      + source_dest_check                    = true
      + subnet_id                            = (known after apply)
      + tags                                 = {
          + "Name" = "aakulov-aws4"
        }
      + tags_all                             = {
          + "Name" = "aakulov-aws4"
        }
      + tenancy                              = (known after apply)
      + user_data                            = (known after apply)
      + user_data_base64                     = (known after apply)
      + vpc_security_group_ids               = (known after apply)

      + capacity_reservation_specification {
          + capacity_reservation_preference = (known after apply)

          + capacity_reservation_target {
              + capacity_reservation_id = (known after apply)
            }
        }

      + ebs_block_device {
          + delete_on_termination = (known after apply)
          + device_name           = (known after apply)
          + encrypted             = (known after apply)
          + iops                  = (known after apply)
          + kms_key_id            = (known after apply)
          + snapshot_id           = (known after apply)
          + tags                  = (known after apply)
          + throughput            = (known after apply)
          + volume_id             = (known after apply)
          + volume_size           = (known after apply)
          + volume_type           = (known after apply)
        }

      + enclave_options {
          + enabled = (known after apply)
        }

      + ephemeral_block_device {
          + device_name  = (known after apply)
          + no_device    = (known after apply)
          + virtual_name = (known after apply)
        }

      + metadata_options {
          + http_endpoint               = "enabled"
          + http_put_response_hop_limit = (known after apply)
          + http_tokens                 = "required"
        }

      + network_interface {
          + delete_on_termination = (known after apply)
          + device_index          = (known after apply)
          + network_interface_id  = (known after apply)
        }

      + root_block_device {
          + delete_on_termination = (known after apply)
          + device_name           = (known after apply)
          + encrypted             = (known after apply)
          + iops                  = (known after apply)
          + kms_key_id            = (known after apply)
          + tags                  = (known after apply)
          + throughput            = (known after apply)
          + volume_id             = (known after apply)
          + volume_size           = (known after apply)
          + volume_type           = (known after apply)
        }
    }

  # aws_internet_gateway.igw will be created
  + resource "aws_internet_gateway" "igw" {
      + arn      = (known after apply)
      + id       = (known after apply)
      + owner_id = (known after apply)
      + tags     = {
          + "Name" = "aakulov-aws4"
        }
      + tags_all = {
          + "Name" = "aakulov-aws4"
        }
      + vpc_id   = (known after apply)
    }

  # aws_nat_gateway.nat will be created
  + resource "aws_nat_gateway" "nat" {
      + allocation_id        = (known after apply)
      + connectivity_type    = "public"
      + id                   = (known after apply)
      + network_interface_id = (known after apply)
      + private_ip           = (known after apply)
      + public_ip            = (known after apply)
      + subnet_id            = (known after apply)
      + tags                 = {
          + "Name" = "aakulov-aws4"
        }
      + tags_all             = {
          + "Name" = "aakulov-aws4"
        }
    }

  # aws_route53_record.aws4 will be created
  + resource "aws_route53_record" "aws4" {
      + allow_overwrite = true
      + fqdn            = (known after apply)
      + id              = (known after apply)
      + name            = "tfe4.anton.hashicorp-success.com"
      + records         = (known after apply)
      + ttl             = 300
      + type            = "A"
      + zone_id         = "Z077919913NMEBCGB4WS0"
    }

  # aws_route_table.aws4-private will be created
  + resource "aws_route_table" "aws4-private" {
      + arn              = (known after apply)
      + id               = (known after apply)
      + owner_id         = (known after apply)
      + propagating_vgws = (known after apply)
      + route            = [
          + {
              + carrier_gateway_id         = ""
              + cidr_block                 = "0.0.0.0/0"
              + destination_prefix_list_id = ""
              + egress_only_gateway_id     = ""
              + gateway_id                 = ""
              + instance_id                = ""
              + ipv6_cidr_block            = ""
              + local_gateway_id           = ""
              + nat_gateway_id             = (known after apply)
              + network_interface_id       = ""
              + transit_gateway_id         = ""
              + vpc_endpoint_id            = ""
              + vpc_peering_connection_id  = ""
            },
        ]
      + tags             = {
          + "Name" = "aakulov-aws4-private"
        }
      + tags_all         = {
          + "Name" = "aakulov-aws4-private"
        }
      + vpc_id           = (known after apply)
    }

  # aws_route_table.aws4-public will be created
  + resource "aws_route_table" "aws4-public" {
      + arn              = (known after apply)
      + id               = (known after apply)
      + owner_id         = (known after apply)
      + propagating_vgws = (known after apply)
      + route            = [
          + {
              + carrier_gateway_id         = ""
              + cidr_block                 = "0.0.0.0/0"
              + destination_prefix_list_id = ""
              + egress_only_gateway_id     = ""
              + gateway_id                 = (known after apply)
              + instance_id                = ""
              + ipv6_cidr_block            = ""
              + local_gateway_id           = ""
              + nat_gateway_id             = ""
              + network_interface_id       = ""
              + transit_gateway_id         = ""
              + vpc_endpoint_id            = ""
              + vpc_peering_connection_id  = ""
            },
        ]
      + tags             = {
          + "Name" = "aakulov-aws4-public"
        }
      + tags_all         = {
          + "Name" = "aakulov-aws4-public"
        }
      + vpc_id           = (known after apply)
    }

  # aws_route_table_association.aws4-private will be created
  + resource "aws_route_table_association" "aws4-private" {
      + id             = (known after apply)
      + route_table_id = (known after apply)
      + subnet_id      = (known after apply)
    }

  # aws_route_table_association.aws4-public will be created
  + resource "aws_route_table_association" "aws4-public" {
      + id             = (known after apply)
      + route_table_id = (known after apply)
      + subnet_id      = (known after apply)
    }

  # aws_s3_bucket.aws4 will be created
  + resource "aws_s3_bucket" "aws4" {
      + acceleration_status         = (known after apply)
      + acl                         = "private"
      + arn                         = (known after apply)
      + bucket                      = "aakulov-aws4-tfe-data"
      + bucket_domain_name          = (known after apply)
      + bucket_regional_domain_name = (known after apply)
      + force_destroy               = true
      + hosted_zone_id              = (known after apply)
      + id                          = (known after apply)
      + region                      = (known after apply)
      + request_payer               = (known after apply)
      + tags                        = {
          + "Name" = "aakulov-aws4-tfe-data"
        }
      + tags_all                    = {
          + "Name" = "aakulov-aws4-tfe-data"
        }
      + website_domain              = (known after apply)
      + website_endpoint            = (known after apply)

      + versioning {
          + enabled    = (known after apply)
          + mfa_delete = (known after apply)
        }
    }

  # aws_s3_bucket_public_access_block.aws4 will be created
  + resource "aws_s3_bucket_public_access_block" "aws4" {
      + block_public_acls       = true
      + block_public_policy     = true
      + bucket                  = (known after apply)
      + id                      = (known after apply)
      + ignore_public_acls      = true
      + restrict_public_buckets = true
    }

  # aws_security_group.aakulov-aws4 will be created
  + resource "aws_security_group" "aakulov-aws4" {
      + arn                    = (known after apply)
      + description            = "Managed by Terraform"
      + egress                 = [
          + {
              + cidr_blocks      = [
                  + "0.0.0.0/0",
                ]
              + description      = ""
              + from_port        = 0
              + ipv6_cidr_blocks = []
              + prefix_list_ids  = []
              + protocol         = "-1"
              + security_groups  = []
              + self             = false
              + to_port          = 0
            },
        ]
      + id                     = (known after apply)
      + ingress                = [
          + {
              + cidr_blocks      = [
                  + "0.0.0.0/0",
                ]
              + description      = ""
              + from_port        = 22
              + ipv6_cidr_blocks = []
              + prefix_list_ids  = []
              + protocol         = "tcp"
              + security_groups  = []
              + self             = false
              + to_port          = 22
            },
          + {
              + cidr_blocks      = [
                  + "0.0.0.0/0",
                ]
              + description      = ""
              + from_port        = 443
              + ipv6_cidr_blocks = []
              + prefix_list_ids  = []
              + protocol         = "tcp"
              + security_groups  = []
              + self             = false
              + to_port          = 443
            },
          + {
              + cidr_blocks      = [
                  + "0.0.0.0/0",
                ]
              + description      = ""
              + from_port        = 80
              + ipv6_cidr_blocks = []
              + prefix_list_ids  = []
              + protocol         = "tcp"
              + security_groups  = []
              + self             = false
              + to_port          = 80
            },
          + {
              + cidr_blocks      = [
                  + "0.0.0.0/0",
                ]
              + description      = ""
              + from_port        = 8800
              + ipv6_cidr_blocks = []
              + prefix_list_ids  = []
              + protocol         = "tcp"
              + security_groups  = []
              + self             = false
              + to_port          = 8800
            },
          + {
              + cidr_blocks      = []
              + description      = ""
              + from_port        = 5432
              + ipv6_cidr_blocks = []
              + prefix_list_ids  = []
              + protocol         = "tcp"
              + security_groups  = []
              + self             = true
              + to_port          = 5432
            },
        ]
      + name                   = "aakulov-aws4-sg"
      + name_prefix            = (known after apply)
      + owner_id               = (known after apply)
      + revoke_rules_on_delete = false
      + tags                   = {
          + "Name" = "aakulov-aws4-sg"
        }
      + tags_all               = {
          + "Name" = "aakulov-aws4-sg"
        }
      + vpc_id                 = (known after apply)
    }

  # aws_security_group.aws4-internal-sg will be created
  + resource "aws_security_group" "aws4-internal-sg" {
      + arn                    = (known after apply)
      + description            = "Managed by Terraform"
      + egress                 = [
          + {
              + cidr_blocks      = [
                  + "0.0.0.0/0",
                ]
              + description      = ""
              + from_port        = 0
              + ipv6_cidr_blocks = []
              + prefix_list_ids  = []
              + protocol         = "-1"
              + security_groups  = []
              + self             = false
              + to_port          = 0
            },
        ]
      + id                     = (known after apply)
      + ingress                = [
          + {
              + cidr_blocks      = [
                  + "0.0.0.0/0",
                ]
              + description      = ""
              + from_port        = -1
              + ipv6_cidr_blocks = []
              + prefix_list_ids  = []
              + protocol         = "icmp"
              + security_groups  = []
              + self             = false
              + to_port          = -1
            },
          + {
              + cidr_blocks      = [
                  + "0.0.0.0/0",
                ]
              + description      = ""
              + from_port        = 22
              + ipv6_cidr_blocks = []
              + prefix_list_ids  = []
              + protocol         = "tcp"
              + security_groups  = []
              + self             = false
              + to_port          = 22
            },
          + {
              + cidr_blocks      = [
                  + "0.0.0.0/0",
                ]
              + description      = ""
              + from_port        = 443
              + ipv6_cidr_blocks = []
              + prefix_list_ids  = []
              + protocol         = "tcp"
              + security_groups  = []
              + self             = false
              + to_port          = 443
            },
          + {
              + cidr_blocks      = [
                  + "0.0.0.0/0",
                ]
              + description      = ""
              + from_port        = 80
              + ipv6_cidr_blocks = []
              + prefix_list_ids  = []
              + protocol         = "tcp"
              + security_groups  = []
              + self             = false
              + to_port          = 80
            },
          + {
              + cidr_blocks      = []
              + description      = ""
              + from_port        = 80
              + ipv6_cidr_blocks = []
              + prefix_list_ids  = []
              + protocol         = "tcp"
              + security_groups  = (known after apply)
              + self             = false
              + to_port          = 80
            },
        ]
      + name                   = "aakulov-aws4-internal-sg"
      + name_prefix            = (known after apply)
      + owner_id               = (known after apply)
      + revoke_rules_on_delete = false
      + tags                   = {
          + "Name" = "aakulov-aws4-internal-sg"
        }
      + tags_all               = {
          + "Name" = "aakulov-aws4-internal-sg"
        }
      + vpc_id                 = (known after apply)
    }

  # aws_subnet.subnet_private will be created
  + resource "aws_subnet" "subnet_private" {
      + arn                             = (known after apply)
      + assign_ipv6_address_on_creation = false
      + availability_zone               = "eu-central-1b"
      + availability_zone_id            = (known after apply)
      + cidr_block                      = "10.5.1.0/24"
      + id                              = (known after apply)
      + ipv6_cidr_block_association_id  = (known after apply)
      + map_public_ip_on_launch         = false
      + owner_id                        = (known after apply)
      + tags_all                        = (known after apply)
      + vpc_id                          = (known after apply)
    }

  # aws_subnet.subnet_private1 will be created
  + resource "aws_subnet" "subnet_private1" {
      + arn                             = (known after apply)
      + assign_ipv6_address_on_creation = false
      + availability_zone               = "eu-central-1c"
      + availability_zone_id            = (known after apply)
      + cidr_block                      = "10.5.3.0/24"
      + id                              = (known after apply)
      + ipv6_cidr_block_association_id  = (known after apply)
      + map_public_ip_on_launch         = false
      + owner_id                        = (known after apply)
      + tags_all                        = (known after apply)
      + vpc_id                          = (known after apply)
    }

  # aws_subnet.subnet_public will be created
  + resource "aws_subnet" "subnet_public" {
      + arn                             = (known after apply)
      + assign_ipv6_address_on_creation = false
      + availability_zone               = "eu-central-1b"
      + availability_zone_id            = (known after apply)
      + cidr_block                      = "10.5.2.0/24"
      + id                              = (known after apply)
      + ipv6_cidr_block_association_id  = (known after apply)
      + map_public_ip_on_launch         = false
      + owner_id                        = (known after apply)
      + tags_all                        = (known after apply)
      + vpc_id                          = (known after apply)
    }

  # aws_subnet.subnet_public1 will be created
  + resource "aws_subnet" "subnet_public1" {
      + arn                             = (known after apply)
      + assign_ipv6_address_on_creation = false
      + availability_zone               = "eu-central-1c"
      + availability_zone_id            = (known after apply)
      + cidr_block                      = "10.5.4.0/24"
      + id                              = (known after apply)
      + ipv6_cidr_block_association_id  = (known after apply)
      + map_public_ip_on_launch         = false
      + owner_id                        = (known after apply)
      + tags_all                        = (known after apply)
      + vpc_id                          = (known after apply)
    }

  # aws_vpc.vpc will be created
  + resource "aws_vpc" "vpc" {
      + arn                              = (known after apply)
      + assign_generated_ipv6_cidr_block = false
      + cidr_block                       = "10.5.0.0/16"
      + default_network_acl_id           = (known after apply)
      + default_route_table_id           = (known after apply)
      + default_security_group_id        = (known after apply)
      + dhcp_options_id                  = (known after apply)
      + enable_classiclink               = (known after apply)
      + enable_classiclink_dns_support   = (known after apply)
      + enable_dns_hostnames             = true
      + enable_dns_support               = true
      + id                               = (known after apply)
      + instance_tenancy                 = "default"
      + ipv6_association_id              = (known after apply)
      + ipv6_cidr_block                  = (known after apply)
      + main_route_table_id              = (known after apply)
      + owner_id                         = (known after apply)
      + tags                             = {
          + "Name" = "aakulov-aws4"
        }
      + tags_all                         = {
          + "Name" = "aakulov-aws4"
        }
    }

  # tls_private_key.aws4 will be created
  + resource "tls_private_key" "aws4" {
      + algorithm                  = "RSA"
      + ecdsa_curve                = "P224"
      + id                         = (known after apply)
      + private_key_pem            = (sensitive value)
      + public_key_fingerprint_md5 = (known after apply)
      + public_key_openssh         = (known after apply)
      + public_key_pem             = (known after apply)
      + rsa_bits                   = 2048
    }

  # tls_self_signed_cert.aws4 will be created
  + resource "tls_self_signed_cert" "aws4" {
      + allowed_uses          = [
          + "key_encipherment",
          + "digital_signature",
          + "server_auth",
        ]
      + cert_pem              = (known after apply)
      + dns_names             = [
          + "tfe4.anton.hashicorp-success.com",
        ]
      + early_renewal_hours   = 744
      + id                    = (known after apply)
      + key_algorithm         = "RSA"
      + private_key_pem       = (sensitive value)
      + ready_for_renewal     = true
      + validity_end_time     = (known after apply)
      + validity_period_hours = 8928
      + validity_start_time   = (known after apply)

      + subject {
          + common_name  = "tfe4.anton.hashicorp-success.com"
          + organization = "aakulov sandbox"
        }
    }

Plan: 25 to add, 0 to change, 0 to destroy.

Changes to Outputs:
  + aws_url = "tfe4.anton.hashicorp-success.com"

Do you want to perform these actions?
  Terraform will perform the actions described above.
  Only 'yes' will be accepted to approve.

  Enter a value: yes

tls_private_key.aws4: Creating...
tls_private_key.aws4: Creation complete after 0s [id=a372886526ca2381e9134dc23125b0d4fa7021ec]
tls_self_signed_cert.aws4: Creating...
tls_self_signed_cert.aws4: Creation complete after 0s [id=99195681611644099882134339610867480656]
aws_vpc.vpc: Creating...
aws_eip.aws4: Creating...
aws_iam_role.aakulov-aws4-iam-role-ec2-s3: Creating...
aws_s3_bucket.aws4: Creating...
aws_eip.aws4: Creation complete after 0s [id=eipalloc-346c683c]
aws_s3_bucket.aws4: Creation complete after 2s [id=aakulov-aws4-tfe-data]
aws_s3_bucket_public_access_block.aws4: Creating...
aws_s3_bucket_public_access_block.aws4: Creation complete after 1s [id=aakulov-aws4-tfe-data]
aws_iam_role.aakulov-aws4-iam-role-ec2-s3: Creation complete after 3s [id=aakulov-aws4-iam-role-ec2-s3]
aws_iam_role_policy.aakulov-aws4-ec2-s3: Creating...
aws_iam_instance_profile.aakulov-aws4-ec2-s3: Creating...
aws_iam_role_policy.aakulov-aws4-ec2-s3: Creation complete after 2s [id=aakulov-aws4-iam-role-ec2-s3:aakulov-aws4-ec2-s3]
aws_iam_instance_profile.aakulov-aws4-ec2-s3: Creation complete after 3s [id=aakulov-aws4-ec2-s3]
aws_vpc.vpc: Still creating... [10s elapsed]
aws_vpc.vpc: Creation complete after 12s [id=vpc-09acc4a6cd94a96e5]
aws_internet_gateway.igw: Creating...
aws_subnet.subnet_private1: Creating...
aws_subnet.subnet_public: Creating...
aws_subnet.subnet_private: Creating...
aws_subnet.subnet_public1: Creating...
aws_security_group.aakulov-aws4: Creating...
aws_subnet.subnet_public: Creation complete after 1s [id=subnet-0092553fbbe7884fe]
aws_subnet.subnet_private: Creation complete after 1s [id=subnet-0a5652ed9299f05ce]
aws_subnet.subnet_private1: Creation complete after 1s [id=subnet-0dd5322de2c15cf57]
aws_subnet.subnet_public1: Creation complete after 1s [id=subnet-042cd18fcfbddf471]
aws_internet_gateway.igw: Creation complete after 1s [id=igw-01716ad30d97028f2]
aws_nat_gateway.nat: Creating...
aws_db_subnet_group.aws4: Creating...
aws_route_table.aws4-public: Creating...
aws_security_group.aakulov-aws4: Creation complete after 2s [id=sg-01c2bd8558a870e9f]
aws_security_group.aws4-internal-sg: Creating...
aws_route_table.aws4-public: Creation complete after 1s [id=rtb-0e5c024685a1de2b3]
aws_route_table_association.aws4-public: Creating...
aws_db_subnet_group.aws4: Creation complete after 1s [id=aakulov-aws4]
aws_db_instance.aws4: Creating...
aws_route_table_association.aws4-public: Creation complete after 0s [id=rtbassoc-03cdf6861d837bcc8]
aws_security_group.aws4-internal-sg: Creation complete after 2s [id=sg-0ba10f61690fe98fd]
aws_nat_gateway.nat: Still creating... [10s elapsed]
aws_db_instance.aws4: Still creating... [10s elapsed]
aws_nat_gateway.nat: Still creating... [20s elapsed]
aws_db_instance.aws4: Still creating... [20s elapsed]
aws_nat_gateway.nat: Still creating... [30s elapsed]
aws_db_instance.aws4: Still creating... [30s elapsed]
aws_nat_gateway.nat: Still creating... [40s elapsed]
aws_db_instance.aws4: Still creating... [40s elapsed]
aws_nat_gateway.nat: Still creating... [50s elapsed]
aws_db_instance.aws4: Still creating... [50s elapsed]
aws_nat_gateway.nat: Still creating... [1m0s elapsed]
aws_db_instance.aws4: Still creating... [1m0s elapsed]
aws_nat_gateway.nat: Still creating... [1m10s elapsed]
aws_db_instance.aws4: Still creating... [1m10s elapsed]
aws_nat_gateway.nat: Still creating... [1m20s elapsed]
aws_db_instance.aws4: Still creating... [1m20s elapsed]
aws_nat_gateway.nat: Still creating... [1m30s elapsed]
aws_db_instance.aws4: Still creating... [1m30s elapsed]
aws_nat_gateway.nat: Still creating... [1m40s elapsed]
aws_db_instance.aws4: Still creating... [1m40s elapsed]
aws_nat_gateway.nat: Creation complete after 1m45s [id=nat-09736af1d48fb0ccc]
aws_route_table.aws4-private: Creating...
aws_route_table.aws4-private: Creation complete after 1s [id=rtb-074dc4ba9c4794e79]
aws_route_table_association.aws4-private: Creating...
aws_route_table_association.aws4-private: Creation complete after 1s [id=rtbassoc-070e0afac1e9cab56]
aws_db_instance.aws4: Still creating... [1m50s elapsed]
aws_db_instance.aws4: Still creating... [2m0s elapsed]
aws_db_instance.aws4: Still creating... [2m10s elapsed]
aws_db_instance.aws4: Still creating... [2m20s elapsed]
aws_db_instance.aws4: Still creating... [2m30s elapsed]
aws_db_instance.aws4: Still creating... [2m40s elapsed]
aws_db_instance.aws4: Still creating... [2m50s elapsed]
aws_db_instance.aws4: Still creating... [3m0s elapsed]
aws_db_instance.aws4: Still creating... [3m10s elapsed]
aws_db_instance.aws4: Still creating... [3m20s elapsed]
aws_db_instance.aws4: Still creating... [3m30s elapsed]
aws_db_instance.aws4: Still creating... [3m40s elapsed]
aws_db_instance.aws4: Creation complete after 3m45s [id=terraform-20210913134904991500000001]
data.template_file.install_tfe_sh: Reading...
data.template_file.install_tfe_sh: Read complete after 0s [id=8dc1471b886888ddde7e23c3958def961d91d05989d644882bef5c3293a4a195]
data.template_cloudinit_config.aws4_cloudinit: Reading...
data.template_cloudinit_config.aws4_cloudinit: Read complete after 0s [id=2465084629]
aws_instance.aws4: Creating...
aws_instance.aws4: Still creating... [10s elapsed]
aws_instance.aws4: Still creating... [20s elapsed]
aws_instance.aws4: Creation complete after 24s [id=i-0f2a2703a1ce72e67]
aws_route53_record.aws4: Creating...
aws_route53_record.aws4: Still creating... [10s elapsed]
aws_route53_record.aws4: Still creating... [20s elapsed]
aws_route53_record.aws4: Still creating... [30s elapsed]
aws_route53_record.aws4: Still creating... [40s elapsed]
aws_route53_record.aws4: Creation complete after 47s [id=Z077919913NMEBCGB4WS0_tfe4.anton.hashicorp-success.com_A]

Apply complete! Resources: 25 added, 0 changed, 0 destroyed.

Outputs:

aws_url = "tfe4.anton.hashicorp-success.com"
```

