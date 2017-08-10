#!/bin/sh

if [ $# -ne 2 ]; then
    echo "usage: $0 kernel database"
    exit
fi

./makedb "$1" "$2" \
    `./kexty -solve "$1" __ZN6OSKext21withPrelinkedInfoDictEP12OSDictionary`
