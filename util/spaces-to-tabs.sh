#!/bin/bash

while [ $# -gt 0 ]; do
    sed -i -E 's/^[[:space:]]{4}/\x9/g' "$1" || exit $?
    shift
done
