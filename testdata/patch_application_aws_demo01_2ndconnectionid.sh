#!/bin/bash

CONNECTIONID=$(curl -s http://localhost:5678/v1/connectionmgmt/connections/aws | jq -r '.awsconnections[1].id')
APPLICATIONID=$(curl -s http://localhost:5679/v1/applicationmgmt/applications | jq -r '.applications[0].id') 

curl -X PATCH http://localhost:5679/v1/applicationmgmt/application/$APPLICATIONID \
    -H "Content-Type: application/json"  \
    -d "{\"connectionid\": \"$CONNECTIONID\"}" | jq