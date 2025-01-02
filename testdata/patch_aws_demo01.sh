#!/bin/bash

ACCESS_KEY=$(vault kv get -tls-skip-verify -mount="kv" "DEMOSERVER\AWS_DEMO01_TEST02" | grep 'access_key' | awk '{print $2}')
SECRET_KEY=$(vault kv get -tls-skip-verify -mount="kv" "DEMOSERVER\AWS_DEMO01_TEST02" | grep 'secret_key' | awk '{print $2}')

curl -X PATCH http://localhost:5678/v1/connectionmgmt/connection/aws/929f0618-0454-4505-94bb-9257856d2b4d \
    -H "Content-Type: application/json"  \
    -d "{\"connectionid\": \"ad6629cf-cbea-4419-ab77-86003f60c2d1\"}" | jq