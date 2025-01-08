#!/bin/bash

curl -X POST http://localhost:5679/v1/applicationmgmt/application \
    -H "Content-Type: application/json"  \
    -d "{\"name\": \"aws_demo01_5\", \"state\": \"activated\"}" | jq