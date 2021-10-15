#!/bin/bash

CAPFILE=./tests/pcap/engeem/CAP_trace20200908085900-test.cap
#CAPFILE=./tests/pcap/engeem/BearerS1U-20200416185559.PCAP
export LD_LIBRARY_PATH=/home/dsokoloski/netify-daemon/src/.libs

exec valgrind --leak-check=full --log-file=/tmp/netifyd-vg-%p.log ./src/.libs/netifyd -d -c ./src/netifyd.conf -t --thread-detection-cores 1 -I lo,${CAPFILE}
