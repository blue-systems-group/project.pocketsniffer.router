#!/bin/bash

for ap in ap1 ap4
do
    scp *.py $ap:projects/pocketsniffer/
done
