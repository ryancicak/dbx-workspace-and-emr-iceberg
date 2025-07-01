# dbx-workspace-and-emr-iceberg
Spin-up a Databricks Workspace (with UC Catalog) + EMR Spark, to read/write UC Managed Iceberg tables. EMR Spark is reading/writing to UC via Iceberg Rest Catalog.


Add a terraform.tfvars with the following (Change the values below):
```hcl
prefix                = "<yourprefix>"
client_id             = "<oauth_serviceprincipal_yourclidentid>"
client_secret         = "<oauth_serviceprincipal_yourclientsecret>"
databricks_account_id = "<yourdatabricksaccountuuid>"
tags = {
  Owner       = "<youremail>"
  Environment = "<test-dev>"
  Budget      = "somebudgetspec_ifexists”
}
region = "<us-east-2>”
allowed_ssh_cidr_blocks = ["<your.ip.address.here/32>"]
release_label = "emr-7.9.0"
applications  = ["Spark"]
databricks_uc_aws_account_id = "<yourdatabricksaccount_id>"
