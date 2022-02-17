#!/bin/bash

# https://www.iana.org/assignments/tls-extensiontype-values/tls-extensiontype-values.xhtml#alpn-protocol-ids

echo -n "#define ND_TLS_ALPN_MAX "
egrep -v '(^Proto|Reserved)' ./doc/alpn-protocol-ids.csv |\
    sed \
        -e 's/^.*,["]*0x/0x/g' \
        -e 's/ (.*//g' \
        -e 's/0x[0-9a-fA-F]*/X/g' \
        -e 's/[[:space:]]*//g' | sort | tail -n 1 | wc -c

egrep -v '(^Proto|Reserved)' ./doc/alpn-protocol-ids.csv |\
    sed \
        -e 's/^.*,["]*0x/0x/g' \
        -e 's/(["“]*/\/* /g' \
        -e 's/["”]*).*$/ *\//g' \
        -e 's/ 0x/, 0x/g' \
        -e 's/^/    { { /g' \
        -e 's/$/, 0x00 }, ND_PROTO_UNKNOWN },/g'

echo "{ { 0x64, 0x6F, 0x71 /* doq */, 0x00 }, ND_PROTO_DOQ },"

exit 0
