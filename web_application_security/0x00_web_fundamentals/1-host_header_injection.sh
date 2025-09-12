#!/bin/bash
curl -d $3  -H "Host:$1"  -X POST $2
