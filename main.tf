terraform {
  required_providers {
    databricks = {
      source  = "databricks/databricks"
      version = "1.83.0"
    }
    aws = {
      source  = "hashicorp/aws"
      version = ">= 5.0.0"
    }
    random = {
      source  = "hashicorp/random"
      version = ">= 3.0.0"
    }
    time = {
      source  = "hashicorp/time"
      version = ">= 0.9.1"
    }
  }
}
provider "aws" {
  region = var.region
}
locals {
  prefix = var.prefix
}
provider "databricks" {
  alias         = "account"
  host          = "https://accounts.cloud.databricks.com"
  account_id    = var.databricks_account_id
  client_id     = var.client_id
  client_secret = var.client_secret
}
provider "databricks" {
  alias         = "workspace"
  host          = databricks_mws_workspaces.workspace.workspace_url
  account_id    = var.databricks_account_id
  client_id     = var.client_id
  client_secret = var.client_secret
}
resource "aws_security_group" "emr" {
  name        = "${var.prefix}-emr-sg"
  description = "Security group for EMR cluster"
  vpc_id      = data.aws_vpc.workspace.id

  ingress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    self        = true
    description = "Allow all traffic within the security group"
  }
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = var.allowed_ssh_cidr_blocks
    description = "SSH access"
  }
  ingress {
    from_port   = 9443
    to_port     = 9443
    protocol    = "tcp"
    cidr_blocks = [data.aws_vpc.workspace.cidr_block]
    description = "Allow EMR internal communication (9443)"
  }

  ingress {
    from_port   = 8443
    to_port     = 8443
    protocol    = "tcp"
    cidr_blocks = [data.aws_vpc.workspace.cidr_block]
    description = "Allow EMR internal communication (8443)"
  }
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
    description = "Allow all outbound traffic"
  }
}
data "aws_caller_identity" "current" {}
data "aws_availability_zones" "available" { state = "available" }
resource "random_id" "suffix" { byte_length = 4 }
resource "random_id" "creds_suffix" { byte_length = 4 }
resource "time_sleep" "iam_propagation" {
  depends_on      = [aws_iam_role_policy.cross_account_policy]
  create_duration = "30s"
}
data "databricks_group" "admins" {
  provider     = databricks.workspace
  display_name = "admins"
  depends_on = [databricks_mws_workspaces.workspace]
}

resource "databricks_user" "owner" {
  provider  = databricks.workspace
  user_name = var.tags["Owner"]
  force     = true
}

resource "databricks_group_member" "owner_is_admin" {
  provider  = databricks.workspace
  group_id  = data.databricks_group.admins.id
  member_id = databricks_user.owner.id
}

###########################
# --- IAM Role (Trust) ---#
###########################
// start EMR service policy
resource "aws_iam_role" "emr_service_role" {
  name = "${var.prefix}-emr-service-role"
  assume_role_policy = jsonencode({
    Version = "2012-10-17",
    Statement = [{
      Effect = "Allow",
      Principal = { Service = "elasticmapreduce.amazonaws.com" },
      Action = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_role_policy_attachment" "emr_service_role_policy" {
  role       = aws_iam_role.emr_service_role.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonElasticMapReduceRole"
}
//end EMR service policy
// start EMR ec2 policy
resource "aws_iam_role" "emr_ec2_role" {
  name = "${var.prefix}-emr-ec2-role"
  assume_role_policy = jsonencode({
    Version = "2012-10-17",
    Statement = [{
      Effect = "Allow",
      Principal = {
        Service = "ec2.amazonaws.com"
      },
      Action = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_role_policy" "emr_ec2_custom_policy" {
  name = "${var.prefix}-emr-ec2-custom-policy"
  role = aws_iam_role.emr_ec2_role.id
  policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
        Effect = "Allow",
        Action = [
          "ec2:Describe*",
          "s3:*",
          "cloudwatch:*",
          "elasticmapreduce:*",
          "glue:*"
        ],
        Resource = "*"
      }
    ]
  })
}
resource "aws_iam_instance_profile" "emr_ec2_profile" {
  name = "${var.prefix}-emr-ec2-profile"
  role = aws_iam_role.emr_ec2_role.name
}
//end EMR policy
resource "aws_iam_role" "cross_account_role" {
  name = "${var.prefix}-crossaccount"
  assume_role_policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
        Effect = "Allow",
        Principal = {
          AWS = [
            "arn:aws:iam::${var.databricks_uc_aws_account_id}:root"
            ,"arn:aws:iam::${data.aws_caller_identity.current.account_id}:role/${var.prefix}-crossaccount"
          ]
        },
        Action = "sts:AssumeRole",
        Condition = {
          StringEquals = {
            "sts:ExternalId" = var.databricks_account_id
          }
        }
      },
      # Allow Lake Formation and Glue to assume the role (NO ExternalId)
      {
        Effect = "Allow",
        Principal = {
          Service = [
            "lakeformation.amazonaws.com",
            "glue.amazonaws.com"
          ]
        },
        Action = "sts:AssumeRole"
        # No condition block here!
      }
    ]
  })
}
resource "aws_iam_role_policy" "cross_account_policy" {
  name = "${var.prefix}-policy"
  role = aws_iam_role.cross_account_role.id
  policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
	#Glue job      
{
  "Effect": "Allow",
  "Action": [
    "s3:GetObject",
    "s3:ListBucket"
  ],
  "Resource": [
    "arn:aws:s3:::aws-glue-studio-transforms-244479516193-prod-${var.region}",
    "arn:aws:s3:::aws-glue-studio-transforms-244479516193-prod-${var.region}/*"
  ]
},
      # S3 permissions for root bucket
      {
        Effect = "Allow",
        Action = [
          "s3:ListBucket",
          "s3:GetBucketLocation"
        ],
        Resource = [
          "arn:aws:s3:::${aws_s3_bucket.root_storage_bucket.bucket}"
        ]
      },
      {
        Effect = "Allow",
        Action = [
          "s3:PutObject",
          "s3:GetObject",
          "s3:DeleteObject"
        ],
        Resource = [
          "arn:aws:s3:::${aws_s3_bucket.root_storage_bucket.bucket}/*"
        ]
      },
     #GLUE
     { 
      Effect = "Allow",
        Action = [
          "glue:GetDatabase",
          "glue:GetDatabases",
          "glue:GetPartition",
          "glue:GetPartitions",
          "glue:GetTable",
          "glue:GetTables",
          "glue:GetUserDefinedFunction",
          "glue:GetUserDefinedFunctions",
          "glue:BatchGetPartition"
        ],
        Resource = [
          "arn:aws:glue:${var.region}:${data.aws_caller_identity.current.account_id}:catalog",
          "arn:aws:glue:${var.region}:${data.aws_caller_identity.current.account_id}:database/*",
          "arn:aws:glue:${var.region}:${data.aws_caller_identity.current.account_id}:table/*"
        ]
      },
      # S3 permissions for Glue table data
      {
        Effect = "Allow",
        Action = [
          "s3:GetObject",
          "s3:ListBucket"
        ],
        Resource = [
          "arn:aws:s3:::${aws_s3_bucket.root_storage_bucket.bucket}",
          "arn:aws:s3:::${aws_s3_bucket.root_storage_bucket.bucket}/*"
        ]
      }, 
      # Databricks required permissions for workspace creation
      {
        Effect = "Allow",
        Action = [
          "ec2:*",
          "iam:PassRole",
          "iam:GetRole",
          "iam:CreateServiceLinkedRole",
          "ec2:DescribeAvailabilityZones",
          "ec2:DescribeInstances",
          "ec2:DescribeInstanceStatus",
          "ec2:DescribeRouteTables",
          "ec2:DescribeSecurityGroups",
          "ec2:DescribeSubnets",
          "ec2:DescribeVolumes",
          "ec2:DescribeVpcs",
          "ec2:CreateInternetGateway",
          "ec2:CreateVpc",
          "ec2:DeleteVpc",
          "ec2:AllocateAddress",
          "ec2:ReleaseAddress",
          "ec2:DescribeNatGateways",
          "ec2:DeleteNatGateway",
          "ec2:DeleteVpcEndpoints",
          "ec2:CreateRouteTable",
          "ec2:DisassociateRouteTable",
          "ec2:DescribeNetworkInterfaces",
          "ec2:CreateSubnet",
          "ec2:DeleteSubnet",
          "ec2:CreateSecurityGroup",
          "ec2:DeleteSecurityGroup",
          "ec2:AuthorizeSecurityGroupIngress",
          "ec2:AuthorizeSecurityGroupEgress",
          "ec2:RevokeSecurityGroupIngress",
          "ec2:RevokeSecurityGroupEgress",
          "ec2:CreateTags",
          "ec2:DeleteTags",
          "ec2:ModifyVpcAttribute",
          "ec2:CreateNatGateway",
          "ec2:CreateVpcEndpoint",
          "ec2:CreateNetworkInterface",
          "ec2:DeleteNetworkInterface",
          "ec2:AttachInternetGateway",
          "ec2:DetachInternetGateway",
          "ec2:AssociateRouteTable",
          "ec2:ReplaceRouteTableAssociation",
          "ec2:CreateRoute",
          "ec2:DeleteRoute",
          "ec2:ModifySubnetAttribute",
          "ec2:DescribeAddresses",
          "ec2:DescribeTags",
          "ec2:DescribeKeyPairs",
          "ec2:DescribeLaunchTemplates",
          "ec2:DescribeLaunchTemplateVersions",
          "ec2:RunInstances",
          "ec2:TerminateInstances",
          "ec2:StartInstances",
          "ec2:StopInstances",
          "ec2:DescribeImages",
          "ec2:DescribeInstanceTypes",
          "ec2:DescribePlacementGroups",
          "ec2:DescribeSnapshots",
          "ec2:DescribeVolumesModifications",
          "ec2:DescribeVpcAttribute",
          "ec2:DescribeVpcClassicLink",
          "ec2:DescribeVpcClassicLinkDnsSupport",
          "ec2:DescribeVpcEndpoints",
          "ec2:DescribeVpcEndpointServices",
          "ec2:DescribeVpcPeeringConnections"
        ],
        Resource = "*"
      },
      # IAM permissions required by Databricks
      {
        Effect = "Allow",
        Action = [
          "iam:PassRole",
          "iam:GetRole",
          "iam:CreateServiceLinkedRole"
        ],
        Resource = "*"
      }
    ]
  })
}

resource "aws_s3_bucket" "root_storage_bucket" {
  bucket        = "${var.prefix}-rootbucket-${random_id.suffix.hex}"
  force_destroy = true
}
resource "aws_s3_bucket_ownership_controls" "root_storage_ownership" {
  bucket = aws_s3_bucket.root_storage_bucket.id
  rule { object_ownership = "BucketOwnerEnforced" }
}
data "databricks_aws_bucket_policy" "this" {
  bucket = aws_s3_bucket.root_storage_bucket.bucket
}
resource "aws_s3_bucket_policy" "root_bucket_policy" {
  bucket     = aws_s3_bucket.root_storage_bucket.id
  policy     = data.databricks_aws_bucket_policy.this.json
  depends_on = [aws_s3_bucket_ownership_controls.root_storage_ownership]
}
resource "databricks_mws_storage_configurations" "workspace_storage" {
  provider                   = databricks.account
  account_id                 = var.databricks_account_id
  storage_configuration_name = "${var.prefix}-storage"
  bucket_name                = aws_s3_bucket.root_storage_bucket.bucket
}
resource "databricks_mws_credentials" "workspace_creds" {
  provider         = databricks.account
  credentials_name = "${var.prefix}-creds-${random_id.creds_suffix.hex}"
  role_arn         = aws_iam_role.cross_account_role.arn
  depends_on       = [time_sleep.iam_propagation]
}
resource "databricks_mws_workspaces" "workspace" {
  provider                 = databricks.account
  account_id               = var.databricks_account_id
  aws_region               = var.region
  workspace_name           = "${local.prefix}-workspace"
  credentials_id           = databricks_mws_credentials.workspace_creds.credentials_id
  storage_configuration_id = databricks_mws_storage_configurations.workspace_storage.storage_configuration_id
}
resource "databricks_metastore" "metastore" {
  provider      = databricks.account
  name          = "${var.prefix}_metastore"
  region        = var.region
  storage_root  = "s3://${aws_s3_bucket.root_storage_bucket.bucket}/metastore"
  force_destroy = true
  depends_on    = [databricks_mws_workspaces.workspace]
}
resource "databricks_metastore_assignment" "this" {
  provider     = databricks.account
  metastore_id = databricks_metastore.metastore.id
  workspace_id = databricks_mws_workspaces.workspace.workspace_id
}
resource "databricks_storage_credential" "root_cred" {
  provider = databricks.workspace
  name     = "${var.prefix}-root-cred"
  aws_iam_role {
    role_arn = aws_iam_role.cross_account_role.arn
  }
  force_destroy = true
  depends_on = [databricks_metastore_assignment.this]
}
resource "databricks_metastore_data_access" "root_access" {
  provider     = databricks.workspace
  metastore_id = databricks_metastore.metastore.id
  name         = "${var.prefix}-root-access"
  aws_iam_role {
    role_arn = aws_iam_role.cross_account_role.arn
  }
  force_destroy = true
  is_default = true
  depends_on = [databricks_storage_credential.root_cred]
}
resource "databricks_catalog" "catalog" {
  provider       = databricks.workspace
  name           = "${var.prefix}_catalog"
  metastore_id   = databricks_metastore.metastore.id
  isolation_mode = "ISOLATED"
  force_destroy = true
  depends_on     = [databricks_metastore_data_access.root_access]
}
resource "databricks_external_location" "schema_location" {
  provider        = databricks.workspace
  name            = "${var.prefix}-schema-location"
  url             = "s3://${aws_s3_bucket.root_storage_bucket.bucket}/schemas/${var.prefix}_catalog/default"
  credential_name = databricks_storage_credential.root_cred.name
  force_destroy = true
  depends_on      = [databricks_storage_credential.root_cred]
}
resource "databricks_schema" "default_schema" {
  provider     = databricks.workspace
  name         = "default"
  catalog_name = databricks_catalog.catalog.name
  storage_root = databricks_external_location.schema_location.url
  force_destroy = true
  depends_on   = [databricks_external_location.schema_location]
}
resource "databricks_grants" "catalog_grants" {
  provider = databricks.workspace
  catalog  = databricks_catalog.catalog.name
  grant {
    principal  = var.tags["Owner"]
    privileges = ["MANAGE","USE_CATALOG", "CREATE_SCHEMA", "ALL_PRIVILEGES","EXTERNAL USE SCHEMA"]
  }
  grant {
    principal  = "account users"
    privileges = ["USE_CATALOG", "CREATE_SCHEMA"]
  }
  depends_on = [databricks_catalog.catalog]
}
resource "databricks_grants" "schema_grants" {
  provider = databricks.workspace
  schema   = "${databricks_catalog.catalog.name}.default"
  grant {
    principal  = var.tags["Owner"]
    privileges = ["MANAGE","CREATE_TABLE", "USE_SCHEMA", "ALL_PRIVILEGES","EXTERNAL USE SCHEMA"]
  }
  grant {
    principal  = "account users"
    privileges = ["USE_SCHEMA", "CREATE_TABLE", "SELECT", "MODIFY"]
  }
  depends_on = [databricks_schema.default_schema]
}
#NEW EMR
# Find the first VPC in your account/region
data "aws_vpcs" "all" {}

data "aws_vpc" "workspace" {
  id = data.aws_vpcs.all.ids[0]
}

# Find the first subnet in that VPC
data "aws_subnets" "workspace" {
  filter {
    name   = "vpc-id"
    values = [data.aws_vpc.workspace.id]
  }
}
data "aws_subnet" "workspace" {
  id = data.aws_subnets.workspace.ids[0]
}

# Find the first security group in that VPC
data "aws_security_groups" "workspace" {
  filter {
    name   = "vpc-id"
    values = [data.aws_vpc.workspace.id]
  }
}
data "aws_security_group" "workspace" {
  id = data.aws_security_groups.workspace.ids[0]
}
# --- EMR Cluster Resource ---
resource "aws_emr_cluster" "spark_unity_catalog" {
  name          = "${var.prefix}-emr-spark-uc"
  release_label = var.release_label
  applications  = var.applications

ec2_attributes {
    key_name                          = "${var.prefix}_key"
    subnet_id                         = data.aws_subnet.workspace.id
    emr_managed_master_security_group = aws_security_group.emr.id
    emr_managed_slave_security_group  = aws_security_group.emr.id
    instance_profile                  = aws_iam_instance_profile.emr_ec2_profile.name
  }
  service_role = aws_iam_role.emr_service_role.name

  log_uri = "s3://${aws_s3_bucket.root_storage_bucket.bucket}/emr-logs/"

  master_instance_group {
    instance_type = "m5.xlarge"
    instance_count = 1
    # Optionally add ebs_config here
  }

  core_instance_group {
    instance_type = "m5.xlarge"
    instance_count = 2
    # Optionally add ebs_config here
  }

  configurations_json = jsonencode([
   {
    Classification = "iceberg-defaults"
    Properties = {
      "iceberg.enabled" = "true"
    }
  },
  {   
   Classification = "spark-defaults"
    Properties = {
      "spark.sql.catalog.${var.prefix}_catalog" : "org.apache.iceberg.spark.SparkCatalog",
      "spark.sql.catalog.${var.prefix}_catalog.type" : "rest",
      "spark.sql.catalog.${var.prefix}_catalog.rest.auth.type" : "oauth2",
      "spark.sql.catalog.${var.prefix}_catalog.uri" : "${databricks_mws_workspaces.workspace.workspace_url}/api/2.1/unity-catalog/iceberg-rest",
      "spark.sql.catalog.${var.prefix}_catalog.oauth2-server-uri" : "${databricks_mws_workspaces.workspace.workspace_url}/oidc/v1/token",
      "spark.sql.catalog.${var.prefix}_catalog.credential" : "${var.client_id}:${var.client_secret}",
      "spark.sql.catalog.${var.prefix}_catalog.warehouse" : "${var.prefix}_catalog",
      "spark.sql.catalog.${var.prefix}_catalog.scope" : "all-apis",
      "spark.sql.defaultCatalog" : "${var.prefix}_catalog",
      "spark.sql.extensions" : "org.apache.iceberg.spark.extensions.IcebergSparkSessionExtensions",
      "spark.sql.shuffle.partitions" : "1",
      "spark.default.parallelism" : "1"
     }
    }
  ])
}
