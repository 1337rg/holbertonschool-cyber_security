#!/bin/bash
awk '{print $1}' logs.txt | sort | uniq -c | sort -rn | head -1 | awk '{print $1}'
