#!/bin/bash

set -euo pipefail

if [ -z "${TESTDIR:-}" ]; then
    TESTDIR=$(dirname $0)
    export TESTDIR
fi

ND_PCAPS=$(find "${TESTDIR}/pcap/" -name '*.cap.gz' | sort)
NDPI_PCAPS=$(sort "${TESTDIR}/ndpi-pcap-files.txt" | egrep -v '^#' |\
    xargs -n 1 -i find "${TESTDIR}/../libs/ndpi/tests/pcap" -name '{}*cap*' |\
    egrep -v -- '-test.cap$')

PCAPS="$(echo ${ND_PCAPS} ${NDPI_PCAPS} | sort)"

CONF="${TESTDIR}/netifyd-test-pcap.conf"
NETIFYD="${TESTDIR}/../src/.libs/netifyd"
NETWORK=192.168.242.0/24
BOLD=$(tput bold)
NORMAL=$(tput sgr0)

export LD_LIBRARY_PATH="${TESTDIR}/../src/.libs/"

echo -e "\nStarting capture tests..."

run_test() {
    BASE=$(echo $1 | sed -e 's/\.[pc]*ap.*$//')
    NAME=$(basename "${BASE}")
    if echo $1 | egrep -q '\.gz$'; then
        zcat $1 > ${BASE}-test.cap || exit $?
    else
        cat $1 > ${BASE}-test.cap || exit $?
    fi
    echo -e "\n${BOLD}>>> ${NAME}${NORMAL}"
    CMD="${NETIFYD} -t -c $CONF --thread-detection-cores=1 -I lo,${BASE}-test.cap -A $NETWORK -dv"
    if [ "x${WITH_VALGRIND}" == "xyes" ]; then
        CMD="valgrind --tool=memcheck --leak-check=full --track-origins=yes --log-file=/tmp/${NAME}.log ${CMD}"
    else
        ulimit -c unlimited
    fi
    echo $CMD
    $CMD || exit $?
    rm -f ${BASE}-test.cap
}

if [ $# -eq 0 ]; then
    echo "No debug PCAP files specified.  Available PCAPs:"
    for PCAP in $PCAPS; do
        echo $PCAP
    done
    exit 1
else
    while [ $# -gt 0 ]; do
        PCAP=$1
        if [ ! -f "$PCAP" ]; then
            if [ -f "${TESTDIR}/pcap/$1.cap.gz" ]; then
                PCAP="${TESTDIR}/pcap/$1.cap.gz"
            else
                PCAP="${TESTDIR}/../libs/ndpi/tests/pcap/$1\.*cap"
            fi
        fi

        if [ ! -f $PCAP ]; then
            echo "PCAP not found: $PCAP"
            exit 1
        fi
        run_test $PCAP
        shift 1
    done
fi

echo "Debug test complete."

exit 0
