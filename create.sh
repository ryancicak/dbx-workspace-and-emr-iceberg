#!/bin/bash

# Remove any // 
sed -i "" -E '/arn:aws:iam::\${data.aws_caller_identity.current.account_id}:role\/\${var.prefix}-crossaccount/s|^([[:space:]]*,?[[:space:]]*)//+|\1|' main.tf

terraform init

# Step 1: Comment out the self-referencing line
sed -i "" '/"arn:aws:iam::${data.aws_caller_identity.current.account_id}:role\/${var.prefix}-crossaccount"/s/^/\/\//' main.tf

terraform apply -auto-approve

# Step 2: Wait for IAM propagation
sleep 60

# Step 3: Uncomment the self-referencing line
sed -i "" '/^[[:space:]]*\/\/[[:space:]]*,"arn:aws:iam::\${data.aws_caller_identity.current.account_id}:role\/\${var.prefix}-crossaccount"/s|//||' main.tf

terraform apply -auto-approve

sleep 30

terraform apply -auto-approve
