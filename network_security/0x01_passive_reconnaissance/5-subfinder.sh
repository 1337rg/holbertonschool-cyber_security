#!/bin/bash
subfinder -d $1 -silent | tee >(xargs -I{} sh -c 'echo -n "{},"; dig +short {} | head -n1') > "$1.txt"
