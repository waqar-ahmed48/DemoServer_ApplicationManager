#!/bin/bash

curl -X POST http://localhost:5679/v1/applicationmgmt/application \
    -H "Content-Type: application/json"  \
    -d "{\"connection\": {\"name\": \"Demo01Account_AWS_1\",\"description\": \"Demo01Account AWS Account description_1\",\"connectiontype\": \"\"}, \"accesskey\": \"$ACCESS_KEY\", \"secretaccesskey\": \"$SECRET_KEY\", \"default_region\": \"us-east-1\", \"default_lease_ttl\": \"20s\", \"max_lease_ttl\": \"60s\", \"role_name\": \"DemoUser\", \"credential_type\": \"iam_user\", \"policy_arns\": [\"arn:aws:iam::aws:policy/AdministratorAccess\"]}" | jq