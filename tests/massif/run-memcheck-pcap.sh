#!/bin/bash

BASE_PATH="$(dirname $0)/../../"
LD_LIBRARY_PATH="${BASE_PATH}/src/.libs"

run_massif() {
    sudo LD_LIBRARY_PATH=${LD_LIBRARY_PATH} \
        valgrind --tool=memcheck --vgdb=full \
        ${BASE_PATH}/src/.libs/netifyd -c ./netifyd.conf -d -r -I lo,$1
}

while [ $# -gt 0 ]; do
    run_massif $1
    shift 1
done

exit 0
