variable "region" {
  type        = string
  description = "AWS region where resources will be deployed"
}

variable "databricks_account_id" {
  type        = string
  description = "Databricks account ID (from the Account Console)"
}

variable "client_id" {
  type        = string
  description = "Client ID of the Databricks service principal"
}

variable "client_secret" {
  type        = string
  sensitive   = true  # Marks this variable as sensitive (hidden in logs)
  description = "OAuth secret for the Databricks service principal"
}

variable "cidr_block" {
  default = "10.4.0.0/16"
}

variable "prefix" {
  description = "Prefix for resource names"
  type        = string
}

variable "tags" {
  type    = map(string)
  default = {
    Environment = "dev"
  }
}

variable "allowed_ssh_cidr_blocks" {
  description = "List of CIDR blocks allowed SSH access"
  type        = list(string)
  default     = []
}

variable "release_label" {
  description = "Release label for the Amazon EMR release"
  type        = string
}

variable "applications" {
  description = "List of applications for Amazon EMR to install and configure"
  type        = list(string)
}

variable "databricks_uc_aws_account_id" {
  description = "Databricks AWS account ID for Unity Catalog"
  type        =  string
}
