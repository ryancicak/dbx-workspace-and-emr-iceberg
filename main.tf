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

# Databricks account-level provider for multi-workspace services
provider "databricks" {
  alias         = "account"
  host          = "https://accounts.cloud.databricks.com"
  account_id    = var.databricks_account_id
  client_id     = var.client_id
  client_secret = var.client_secret
}

# Workspace-level provider uses the workspace URL once created
provider "databricks" {
  alias         = "workspace"
  host          = databricks_mws_workspaces.workspace.workspace_url
  account_id    = var.databricks_account_id
  client_id     = var.client_id
  client_secret = var.client_secret
}

data "aws_caller_identity" "current" {}
data "aws_availability_zones" "available" {
  state = "available"
}

resource "aws_vpc" "emr" {
  cidr_block           = "10.0.0.0/16"
  enable_dns_hostnames = true
  enable_dns_support   = true
  tags                 = merge(var.tags, { Name = "${var.prefix}-emr-vpc" })
}

resource "aws_internet_gateway" "emr" {
  vpc_id = aws_vpc.emr.id
  tags   = merge(var.tags, { Name = "${var.prefix}-emr-igw" })
}

resource "aws_subnet" "emr" {
  vpc_id                  = aws_vpc.emr.id
  cidr_block              = "10.0.0.0/24"
  availability_zone       = data.aws_availability_zones.available.names[0]
  map_public_ip_on_launch = true
  tags                    = merge(var.tags, { Name = "${var.prefix}-emr-subnet" })
}

resource "aws_route_table" "emr" {
  vpc_id = aws_vpc.emr.id
  tags   = merge(var.tags, { Name = "${var.prefix}-emr-rt" })
}

resource "aws_route" "internet_access" {
  route_table_id         = aws_route_table.emr.id
  destination_cidr_block = "0.0.0.0/0"
  gateway_id             = aws_internet_gateway.emr.id
}

resource "aws_route_table_association" "emr" {
  subnet_id      = aws_subnet.emr.id
  route_table_id = aws_route_table.emr.id
}

# Security group for VPC endpoints
resource "aws_security_group" "vpc_endpoints" {
  name        = "${var.prefix}-vpc-endpoints-sg"
  description = "Security group for VPC endpoints"
  vpc_id      = aws_vpc.emr.id

  ingress {
    from_port       = 443
    to_port         = 443
    protocol        = "tcp"
    security_groups = [aws_security_group.emr.id]
    description     = "HTTPS from EMR security group"
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
    description = "All outbound traffic"
  }

  tags = merge(var.tags, { Name = "${var.prefix}-vpc-endpoints-sg" })
}

# VPC Endpoints for SSM (required for SSM to work reliably)
resource "aws_vpc_endpoint" "ssm" {
  vpc_id              = aws_vpc.emr.id
  service_name        = "com.amazonaws.${var.region}.ssm"
  vpc_endpoint_type   = "Interface"
  subnet_ids          = [aws_subnet.emr.id]
  security_group_ids  = [aws_security_group.vpc_endpoints.id]
  private_dns_enabled = true
  
  tags = merge(var.tags, { Name = "${var.prefix}-ssm-endpoint" })
}

resource "aws_vpc_endpoint" "ssmmessages" {
  vpc_id              = aws_vpc.emr.id
  service_name        = "com.amazonaws.${var.region}.ssmmessages"
  vpc_endpoint_type   = "Interface"
  subnet_ids          = [aws_subnet.emr.id]
  security_group_ids  = [aws_security_group.vpc_endpoints.id]
  private_dns_enabled = true
  
  tags = merge(var.tags, { Name = "${var.prefix}-ssmmessages-endpoint" })
}

resource "aws_vpc_endpoint" "ec2messages" {
  vpc_id              = aws_vpc.emr.id
  service_name        = "com.amazonaws.${var.region}.ec2messages"
  vpc_endpoint_type   = "Interface"
  subnet_ids          = [aws_subnet.emr.id]
  security_group_ids  = [aws_security_group.vpc_endpoints.id]
  private_dns_enabled = true
  
  tags = merge(var.tags, { Name = "${var.prefix}-ec2messages-endpoint" })
}

resource "aws_security_group" "emr" {
  name        = "${var.prefix}-emr-sg"
  description = "Security group for EMR cluster"
  vpc_id      = aws_vpc.emr.id

  # Allow unrestricted intra-SG traffic
  ingress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    self        = true
    description = "Allow all traffic within the security group"
  }

  # SSH access from allowed CIDRs
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = var.allowed_ssh_cidr_blocks
    description = "SSH access"
  }

  # EMR internal ports for Trino and Spark
  ingress {
    from_port   = 9443
    to_port     = 9443
    protocol    = "tcp"
    cidr_blocks = [aws_vpc.emr.cidr_block]
    description = "Allow EMR internal communication (9443)"
  }

  ingress {
    from_port   = 8443
    to_port     = 8443
    protocol    = "tcp"
    cidr_blocks = [aws_vpc.emr.cidr_block]
    description = "Allow EMR internal communication (8443)"
  }

  egress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
    description = "Allow HTTPS outbound"
  }

  # Allow all outbound traffic
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
    description = "Allow all outbound traffic"
  }
}

resource "aws_security_group" "emr_service_access" {
  name        = "${var.prefix}-emr-service-access-sg"
  description = "EMR service access security group for private subnet"
  vpc_id      = aws_vpc.emr.id

  ingress {
    from_port       = 9443
    to_port         = 9443
    protocol        = "tcp"
    security_groups = [aws_security_group.emr.id]
    description     = "Allow EMR managed master security group communication (9443)"
  }

  egress {
    from_port   = 8443
    to_port     = 8443
    protocol    = "tcp"
    cidr_blocks = [aws_vpc.emr.cidr_block]
  }

  egress {
    from_port   = 9443
    to_port     = 9443
    protocol    = "tcp"
    cidr_blocks = [aws_vpc.emr.cidr_block]
  }

  tags = var.tags
}

resource "random_id" "suffix" {
  byte_length = 4
}

resource "random_id" "creds_suffix" {
  byte_length = 4
}

resource "time_sleep" "iam_propagation" {
  depends_on      = [aws_iam_role_policy.cross_account_policy]
  create_duration = "30s"
}

data "databricks_group" "admins" {
  provider     = databricks.workspace
  display_name = "admins"
  depends_on   = [databricks_mws_workspaces.workspace]
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

resource "databricks_token" "emr_pat" {
  provider = databricks.workspace
  comment  = "${var.prefix}-emr-trino-pat"
  lifetime_seconds = 0
  depends_on = [databricks_mws_workspaces.workspace]
}

# Simple cleanup script that runs locally on each node
resource "aws_s3_object" "simple_trino_cleanup_script" {
  bucket = aws_s3_bucket.root_storage_bucket.bucket
  key    = "${var.prefix}/scripts/simple_trino_cleanup.sh"
  content = <<-EOF
#!/bin/bash
# simple_trino_cleanup.sh
# Removes unwanted properties from iceberg.properties and disables hive.properties
# Run this script on each EMR node individually
set -euo pipefail

PROPERTIES_FILE="/etc/trino/conf/catalog/iceberg.properties"
HIVE_CAT_FILE="/etc/trino/conf/catalog/hive.properties"

HOSTNAME="$(hostname)"
echo "Starting Trino cleanup on $HOSTNAME..."

# 1) Clean up iceberg.properties - remove the two unwanted properties
if [[ -f "$PROPERTIES_FILE" ]]; then
    echo "✓ Found $PROPERTIES_FILE, cleaning up..."
    
    # Remove the two problematic lines
    sudo sed -i '/^fs\.hadoop\.enabled/d' "$PROPERTIES_FILE"
    sudo sed -i '/^hive\.metastore\.uri/d' "$PROPERTIES_FILE"
    
    echo "✓ Removed fs.hadoop.enabled and hive.metastore.uri properties"
else
    echo "✗ $PROPERTIES_FILE not found on this node"
fi

# 2) Disable hive catalog by renaming the file
if [[ -f "$HIVE_CAT_FILE" ]]; then
    echo "✓ Found $HIVE_CAT_FILE, disabling..."
    sudo mv "$HIVE_CAT_FILE" "$${HIVE_CAT_FILE}.disabled"
    echo "✓ Disabled hive catalog"
else
    echo "- No hive catalog file found (already disabled or not present)"
fi

# 3) Restart Trino to apply changes
echo "Restarting Trino service..."
if sudo systemctl restart trino-server || sudo systemctl restart trino-server.service; then
    echo "✓ Trino restarted successfully"
else
    echo "✗ Failed to restart Trino"
    exit 1
fi

echo "✓ Cleanup complete on $HOSTNAME!"
EOF
  content_type = "text/x-shellscript"
}

# SSM script that runs the simple cleanup on all nodes
resource "aws_s3_object" "simple_ssm_script" {
  bucket = aws_s3_bucket.root_storage_bucket.bucket
  key    = "${var.prefix}/scripts/simple_ssm.sh"
  content = <<-EOF
#!/bin/bash
# minimal_ssm_cleanup.sh
set -euo pipefail

# Auto-detect cluster ID
CLUSTER_ID="$(sed -n 's/.*"jobFlowId"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' /mnt/var/lib/info/job-flow.json)"

# Get all instance IDs
ALL_INSTANCES=$(aws emr list-instances --cluster-id "$CLUSTER_ID" --query 'Instances[].Ec2InstanceId' --output text)

# Run cleanup on all nodes via SSM
aws ssm send-command \
  --instance-ids $ALL_INSTANCES \
  --document-name "AWS-RunShellScript" \
  --parameters 'commands=["chmod +x /tmp/simple_trino_cleanup.sh","bash /tmp/simple_trino_cleanup.sh"]'

echo "Cleanup commands sent to all nodes!"
EOF
  content_type = "text/x-shellscript"
}

# Bootstrap script to configure SSM and place the simple cleanup script
resource "aws_s3_object" "bootstrap_script" {
  bucket = aws_s3_bucket.root_storage_bucket.bucket
  key    = "${var.prefix}/scripts/bootstrap.sh"
  content = <<-EOF
#!/bin/bash
# bootstrap.sh - Configure SSM and place cleanup script
set -euo pipefail

echo "Configuring SSM Agent..."

# Restart SSM agent to ensure it's running with current IAM role
sudo systemctl restart amazon-ssm-agent
sudo systemctl enable amazon-ssm-agent

echo "Downloading simple cleanup script..."

# Download the simple cleanup script to /tmp/
aws s3 cp s3://${aws_s3_bucket.root_storage_bucket.bucket}/${aws_s3_object.simple_trino_cleanup_script.key} /tmp/simple_trino_cleanup.sh
chmod +x /tmp/simple_trino_cleanup.sh

echo "Bootstrap complete"
EOF
  content_type = "text/x-shellscript"
}

resource "aws_iam_role" "emr_service_role" {
  name = "${var.prefix}-emr-service-role"
  assume_role_policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
        Effect = "Allow",
        Principal = { Service = "elasticmapreduce.amazonaws.com" },
        Action = "sts:AssumeRole"
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "emr_service_role_policy" {
  role       = aws_iam_role.emr_service_role.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonElasticMapReduceRole"
}

resource "aws_iam_role" "emr_ec2_role" {
  name = "${var.prefix}-emr-ec2-role"
  assume_role_policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
        Effect = "Allow",
        Principal = { Service = "ec2.amazonaws.com" },
        Action = "sts:AssumeRole"
      }
    ]
  })
}

# Attach the default EMR EC2 policy
resource "aws_iam_role_policy_attachment" "emr_ec2_instance_profile" {
  role       = aws_iam_role.emr_ec2_role.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonElasticMapReduceforEC2Role"
}

# Attach SSM managed instance policy
resource "aws_iam_role_policy_attachment" "emr_ec2_ssm_managed_instance" {
  role       = aws_iam_role.emr_ec2_role.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
}

# Custom policy for additional permissions including SSM commands
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
          "glue:*",
          "ssm:UpdateInstanceInformation",
          "ssm:SendCommand",
          "ssm:ListCommands",
          "ssm:ListCommandInvocations",
          "ssm:DescribeInstanceInformation",
          "ssm:GetCommandInvocation",
          "ssm:DescribeInstanceProperties",
          "ssm:ListAssociations",
          "ssm:ListInstanceAssociations"
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
        Condition = { StringEquals = { "sts:ExternalId" = var.databricks_account_id } }
      },
      {
        Effect = "Allow",
        Principal = { Service = ["lakeformation.amazonaws.com", "glue.amazonaws.com"] },
        Action = "sts:AssumeRole"
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
      {
        Effect = "Allow",
        Action = ["s3:GetObject", "s3:ListBucket"],
        Resource = [
          "arn:aws:s3:::aws-glue-studio-transforms-244479516193-prod-${var.region}",
          "arn:aws:s3:::aws-glue-studio-transforms-244479516193-prod-${var.region}/*"
        ]
      },
      {
        Effect = "Allow",
        Action = ["s3:ListBucket", "s3:GetBucketLocation"],
        Resource = ["arn:aws:s3:::${aws_s3_bucket.root_storage_bucket.bucket}"]
      },
      {
        Effect = "Allow",
        Action = ["s3:PutObject", "s3:GetObject", "s3:DeleteObject"],
        Resource = ["arn:aws:s3:::${aws_s3_bucket.root_storage_bucket.bucket}/*"]
      },
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
      {
        Effect = "Allow",
        Action = ["s3:GetObject", "s3:ListBucket"],
        Resource = [
          "arn:aws:s3:::${aws_s3_bucket.root_storage_bucket.bucket}",
          "arn:aws:s3:::${aws_s3_bucket.root_storage_bucket.bucket}/*"
        ]
      },
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
      {
        Effect = "Allow",
        Action = ["iam:PassRole", "iam:GetRole", "iam:CreateServiceLinkedRole"],
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
  rule {
    object_ownership = "BucketOwnerEnforced"
  }
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
  depends_on    = [databricks_metastore_assignment.this]
}

resource "databricks_metastore_data_access" "root_access" {
  provider     = databricks.workspace
  metastore_id = databricks_metastore.metastore.id
  name         = "${var.prefix}-root-access"
  aws_iam_role {
    role_arn = aws_iam_role.cross_account_role.arn
  }
  force_destroy = true
  is_default    = true
  depends_on    = [databricks_storage_credential.root_cred]
}

resource "databricks_catalog" "catalog" {
  provider       = databricks.workspace
  name           = "${var.prefix}_catalog"
  metastore_id   = databricks_metastore.metastore.id
  isolation_mode = "ISOLATED"
  force_destroy  = true
  depends_on     = [databricks_metastore_data_access.root_access]
}

resource "databricks_external_location" "schema_location" {
  provider        = databricks.workspace
  name            = "${var.prefix}-schema-location"
  url             = "s3://${aws_s3_bucket.root_storage_bucket.bucket}/schemas/${var.prefix}_catalog/default"
  credential_name = databricks_storage_credential.root_cred.name
  force_destroy   = true
  depends_on      = [databricks_storage_credential.root_cred]
}

resource "databricks_schema" "default_schema" {
  provider      = databricks.workspace
  name          = "default"
  catalog_name  = databricks_catalog.catalog.name
  storage_root  = databricks_external_location.schema_location.url
  force_destroy = true
  depends_on    = [databricks_external_location.schema_location]
}

data "databricks_service_principal" "emr_sp" {
  provider = databricks.account
  application_id = var.client_id
}

resource "databricks_grants" "catalog_grants" {
  provider = databricks.workspace
  catalog  = databricks_catalog.catalog.name
  grant {
    principal  = var.tags["Owner"]
    privileges = ["MANAGE", "USE_CATALOG", "CREATE_SCHEMA", "ALL_PRIVILEGES", "EXTERNAL_USE_SCHEMA"]
  }
  grant {
    principal  = data.databricks_service_principal.emr_sp.application_id
    privileges = ["MANAGE", "USE_CATALOG", "CREATE_SCHEMA", "ALL_PRIVILEGES", "EXTERNAL_USE_SCHEMA"]
  }
  depends_on = [databricks_catalog.catalog]
}

resource "databricks_grants" "schema_grants" {
  provider = databricks.workspace
  schema   = "${databricks_catalog.catalog.name}.default"
  grant {
    principal  = var.tags["Owner"]
    privileges = ["MANAGE", "CREATE_TABLE", "USE_SCHEMA", "ALL_PRIVILEGES", "EXTERNAL_USE_SCHEMA"]
  }
  grant {
    principal  = data.databricks_service_principal.emr_sp.application_id
    privileges = ["MANAGE", "CREATE_TABLE", "USE_SCHEMA", "ALL_PRIVILEGES", "EXTERNAL_USE_SCHEMA"]
  }
  depends_on = [databricks_schema.default_schema]
}

resource "aws_emr_cluster" "spark_unity_catalog" {
  name          = "${var.prefix}-emr-spark-uc"
  release_label = var.release_label
  applications  = var.applications
  
  ec2_attributes {
    key_name                          = "${var.prefix}_key"
    subnet_id                        = aws_subnet.emr.id
    emr_managed_master_security_group = aws_security_group.emr.id
    emr_managed_slave_security_group  = aws_security_group.emr.id
    instance_profile                 = aws_iam_instance_profile.emr_ec2_profile.name
  }
  
  service_role = aws_iam_role.emr_service_role.name
  log_uri      = "s3://${aws_s3_bucket.root_storage_bucket.bucket}/emr-logs/"
  
  master_instance_group {
    instance_type  = "m5.xlarge"
    instance_count = 1
  }
  
  core_instance_group {
    instance_type  = "m5.xlarge"
    instance_count = 2
  }
  
  configurations_json = jsonencode([
    {
      Classification = "iceberg-defaults",
      Properties = {
        "iceberg.enabled" = "true"
      }
    },
    {
      Classification = "spark-defaults",
      Properties = {
        "spark.sql.catalog.${var.prefix}_catalog"                            = "org.apache.iceberg.spark.SparkCatalog",
        "spark.sql.catalog.${var.prefix}_catalog.type"                       = "rest",
        "spark.sql.catalog.${var.prefix}_catalog.rest.auth.type"             = "oauth2",
        "spark.sql.catalog.${var.prefix}_catalog.uri"                        = "${databricks_mws_workspaces.workspace.workspace_url}/api/2.1/unity-catalog/iceberg-rest",
        "spark.sql.catalog.${var.prefix}_catalog.oauth2-server-uri"          = "${databricks_mws_workspaces.workspace.workspace_url}/oidc/v1/token",
        "spark.sql.catalog.${var.prefix}_catalog.credential"                 = "${var.client_id}:${var.client_secret}",
        "spark.sql.catalog.${var.prefix}_catalog.warehouse"                  = "${var.prefix}_catalog",
        "spark.sql.catalog.${var.prefix}_catalog.scope"                      = "all-apis",
        "spark.sql.defaultCatalog"                                           = "${var.prefix}_catalog",
        "spark.sql.extensions"                                                = "org.apache.iceberg.spark.extensions.IcebergSparkSessionExtensions",
        "spark.sql.shuffle.partitions"                                       = "1",
        "spark.default.parallelism"                                          = "1"
      }
    },
    {
      Classification = "trino-connector-iceberg",
      Properties = {
        "connector.name"                              = "iceberg",
        "iceberg.catalog.type"                        = "rest",
        "iceberg.rest-catalog.uri"                    = "${databricks_mws_workspaces.workspace.workspace_url}/api/2.1/unity-catalog/iceberg-rest",
        "iceberg.rest-catalog.warehouse"              = "${var.prefix}_catalog",
        "iceberg.rest-catalog.security"               = "OAUTH2",
        "iceberg.rest-catalog.oauth2.token"           = databricks_token.emr_pat.token_value,
        "fs.native-s3.enabled"                        = "true",
        "s3.region"                                   = var.region
      }
    }
  ])
  
  depends_on = [
    aws_route.internet_access, 
    databricks_token.emr_pat, 
    aws_s3_object.simple_trino_cleanup_script,
    aws_s3_object.simple_ssm_script,
    aws_s3_object.bootstrap_script,
    aws_vpc_endpoint.ssm,
    aws_vpc_endpoint.ssmmessages,
    aws_vpc_endpoint.ec2messages
  ]
  
  # Bootstrap: Configure SSM and place cleanup script on all nodes
  bootstrap_action {
    path = "s3://${aws_s3_bucket.root_storage_bucket.bucket}/${aws_s3_object.bootstrap_script.key}"
    name = "configure-ssm-and-place-cleanup-script"
  }
  
  # Step: Run the simple SSM script to execute cleanup on all nodes
  step {
    name              = "run-simple-ssm-cleanup"
    action_on_failure = "CONTINUE"
    hadoop_jar_step {
      jar = "command-runner.jar"
      args = [
        "bash",
        "-lc",
        "aws s3 cp s3://${aws_s3_bucket.root_storage_bucket.bucket}/${aws_s3_object.simple_ssm_script.key} /tmp/simple_ssm.sh && chmod +x /tmp/simple_ssm.sh && bash /tmp/simple_ssm.sh"
      ]
    }
  }
}
