#!/bin/bash

for ap in $@
do
    scp *.py $ap:projects/pocketsniffer/
    ssh $ap 'pgrep -f "main.py" | xargs kill -9'
    ssh $ap 'projects/pocketsniffer/main.py &'
done
