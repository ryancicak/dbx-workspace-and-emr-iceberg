# dbx-workspace-and-emr-iceberg
Spin-up a Databricks Workspace (with UC Catalog) + EMR Spark or EMR Trino, to read/write UC Managed Iceberg tables. EMR Spark or EMR Trino is reading/writing to UC via Iceberg Rest Catalog.

Pre-req:<br>
#1) You MUST have an EC2 key pair with `<yourprefix>_key` (EMR will use this key pair and if one does not exist, EMR will NOT start up)

#2)
aws cli installed, and run the following with your (Access Key, Secret Key, and Region), prior to running terraform.
```hcl
export AWS_ACCESS_KEY_ID="yourAWSecretkey"
export AWS_SECRET_ACCESS_KEY="yourAWSAccessKey"
export AWS_DEFAULT_REGION="us-east-2"
```

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
applications  = ["Spark"] #Or include "Trino"
databricks_uc_aws_account_id = "<yourdatabricksaccount_id>"
```

If you'd like to connect your existing EMR cluster to UC's IRC, you can use the following (swapping out cicak_catalog for your catalog name, uri for your workspace, and oauth client_id and client_secret):
```hcl
spark-sql \
  --packages org.apache.iceberg:iceberg-spark-runtime-3.5_2.12:1.9.1,org.apache.iceberg:iceberg-aws-bundle:1.9.1 \
  --conf spark.sql.catalog.cicak_catalog=org.apache.iceberg.spark.SparkCatalog \
  --conf spark.sql.catalog.cicak_catalog.type=rest \
  --conf spark.sql.catalog.cicak_catalog.rest.auth.type=oauth2 \
  --conf spark.sql.catalog.cicak_catalog.uri=https://dbc-fa9f7482-be8e.cloud.databricks.com/api/2.1/unity-catalog/iceberg-rest \
  --conf spark.sql.catalog.cicak_catalog.oauth2-server-uri=https://dbc-fa9f7482-be8e.cloud.databricks.com/oidc/v1/token \
  --conf spark.sql.catalog.cicak_catalog.credential=${databricks_client_id}:${databricks_client_secret} \
  --conf spark.sql.catalog.cicak_catalog.warehouse=cicak_catalog \
  --conf spark.sql.catalog.cicak_catalog.scope=all-apis \
  --conf spark.sql.defaultCatalog=cicak_catalog
```

On your Trino coordinator node, run the following command to immediately start interacting with the Unity Catalog Iceberg REST Catalog:
```hcl
/usr/lib/trino/bin/trino-cli-467.amzn.2-executable --server http://localhost:8889 --catalog iceberg
```
