#!/bin/bash
sudo nmap -sF -ff -T2 -p80,85 $1
