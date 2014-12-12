#!/bin/bash

for ap in $@
do
    scp *.py $ap:projects/pocketsniffer/
done
