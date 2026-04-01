#!/bin/bash
set -e

# Fix volume permissions if running as root
if [ "$(id -u)" = '0' ]; then
    chown -R qubitcoin:qubitcoin /home/qubitcoin/.qubitcoin 2>/dev/null || true
    exec gosu qubitcoin "$0" "$@"
fi

# If first argument starts with a dash, prepend qubitcoind
if [ "${1:0:1}" = '-' ]; then
    set -- qubitcoind "$@"
fi

exec "$@"
