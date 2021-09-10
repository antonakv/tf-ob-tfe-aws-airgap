variable "key_name" {}
variable "region" {}
variable "ami" {}
variable "instance_type" {}
variable "cidr_vpc" {}
variable "cidr_subnet1" {}
variable "cidr_subnet2" {}
variable "cidr_subnet3" {}
variable "cidr_subnet4" {}
variable "db_password" {
  type      = string
  sensitive = true
}
variable "enc_password" {
  type      = string
  sensitive = true
}
variable "tfe_hostname" {
  type = string
}