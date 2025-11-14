#!/bin/bash
sudo nmap -sA -p$2 --reason --host-timeout 1000 $1
