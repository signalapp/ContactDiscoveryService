#!/bin/bash

echo "INFO mock child started with args: $*" 1>&2

while [[ "$1" != "--source-fd" ]]; do
    if [[ $# -eq 0 ]]; then
        echo "ERRO no --source-fd specified" 1>&2
        exit 1
    fi
    shift
done

shift
fd=$(echo "$1" | sed -nEe "/^[0-9]+$/p")

if [[ -z "$fd" ]]; then
    echo "ERRO bad --source-fd: $1" 1>&2
    exit 1
fi

while IFS= read -u "$fd" line; do
    printf "received message: %s\n" "$line" 1>&2
    printf "%s\n" "$line" 1>&"${fd}"
done

echo "INFO mock child exiting" 1>&2
