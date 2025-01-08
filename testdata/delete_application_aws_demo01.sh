#!/bin/bash

APPLICATIONID=$(curl -s http://localhost:5679/v1/applicationmgmt/applications | jq -r '.applications[0].id') 
curl -X DELETE http://localhost:5679/v1/applicationmgmt/application/$APPLICATIONID | jq