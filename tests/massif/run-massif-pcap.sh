#!/bin/bash

BASE_PATH="$(dirname $0)/../../"
LD_LIBRARY_PATH="${BASE_PATH}/src/.libs"

run_massif() {
    sudo LD_LIBRARY_PATH=${LD_LIBRARY_PATH} \
        valgrind --tool=massif --time-unit=B \
        ${BASE_PATH}/src/.libs/netifyd -c ./netifyd.conf -d -t -r -I lo,$1
}

while [ $# -gt 0 ]; do
    run_massif $1
    shift 1
done

exit 0
