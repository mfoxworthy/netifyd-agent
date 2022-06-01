#!/bin/bash

set -euo pipefail

if [ -z "${TESTDIR:-}" ]; then
    TESTDIR=$(dirname $0)
    export TESTDIR
fi

ND_PCAPS=$(find "${TESTDIR}/pcap/" -name '*.cap.gz' | sort)
NDPI_PCAPS=$(sort "${TESTDIR}/ndpi-pcap-files.txt" | egrep -v '^#' |\
    xargs -n 1 -i find "${TESTDIR}/../libs/ndpi/tests/pcap" -name '{}*cap' |\
    egrep -v -- '-test.cap$')

PCAPS="$(echo ${ND_PCAPS} ${NDPI_PCAPS} | sort)"

CONF="${TESTDIR}/netifyd-test-pcap.conf"
#SINK_CONF="${TESTDIR}/../deploy/netify-sink.conf"
SINK_CONF="/etc/netify.d/netify-sink.conf"
NETIFYD="${TESTDIR}/../src/.libs/netifyd"
NETWORK=192.168.242.0/24
BOLD=$(tput bold)
NORMAL=$(tput sgr0)

export LD_LIBRARY_PATH="${TESTDIR}/../src/.libs/"

echo -e "\nStarting capture tests..."

run_test() {
    BASE=$(echo $1 | sed -e 's/\.[pc]*ap.*$//')
    NAME=$(basename "${BASE}")
    LOG=$(printf "%s/test-pcap-logs/%s.log" ${TESTDIR} ${NAME})
    if echo $1 | egrep -q '\.gz$'; then
        zcat $1 > ${BASE}-test.cap || exit $?
    else
        cat $1 > ${BASE}-test.cap || exit $?
    fi
    echo -e "\n${BOLD}>>> ${NAME}${NORMAL}"
    CMD="${NETIFYD} -t -c $CONF -f $SINK_CONF --thread-detection-cores=1 -I lo,${BASE}-test.cap -A $NETWORK -T ${LOG}"
    if [ "x${WITH_VALGRIND}" == "xyes" ]; then
        CMD="valgrind --tool=memcheck --leak-check=full --track-origins=yes --log-file=/tmp/${NAME}.log ${CMD}"
    fi
    echo $CMD
    $CMD || exit $?
    rm -f ${BASE}-test.cap
}

if [ $# -eq 0 ]; then
    for PCAP in $PCAPS; do
        run_test $PCAP
    done
else
    while [ $# -gt 0 ]; do
        run_test $1
        shift 1
    done
fi

echo "Capture test complete."

exit 0
