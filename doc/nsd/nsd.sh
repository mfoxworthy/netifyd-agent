#!/bin/bash

FILES=$(ls nsd-*.txt)

for FILE in $FILES; do
    echo -n "$FILE: "
    echo -n "$(cat $FILE)" | base64 -w 0; echo
done

exit 0
