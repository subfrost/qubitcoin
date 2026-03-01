#!/bin/bash
set -e

# If first argument starts with a dash, prepend qubitcoind
if [ "${1:0:1}" = '-' ]; then
    set -- qubitcoind "$@"
fi

exec "$@"
