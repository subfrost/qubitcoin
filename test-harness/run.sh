#!/usr/bin/env bash
# test-harness/run.sh -- Regtest P2P test harness
#
# Sets up a Bitcoin Core regtest node in Docker, mines blocks,
# captures baseline traffic between two Bitcoin Core nodes, then
# connects Qubitcoin and captures its traffic for comparison.
#
# Usage:
#   ./test-harness/run.sh           # full run (baseline + qubitcoin)
#   ./test-harness/run.sh --quick   # skip baseline, only run qubitcoin test

set -euo pipefail
cd "$(dirname "$0")/.."

QUICK=false
[[ "${1:-}" == "--quick" ]] && QUICK=true

PCAP_DIR="/tmp/regtest-pcaps"
LOG_DIR="/tmp/regtest-logs"
mkdir -p "$PCAP_DIR" "$LOG_DIR"

# Cleanup from previous runs
cleanup() {
    echo "=== Cleaning up ==="
    docker stop btc-node-a btc-node-b 2>/dev/null || true
    docker rm btc-node-a btc-node-b 2>/dev/null || true
    docker network rm regtest-net 2>/dev/null || true
    # Kill any leftover tcpdump or qubitcoind
    sudo pkill -f "tcpdump.*regtest" 2>/dev/null || true
    pkill -f "qubitcoind.*regtest" 2>/dev/null || true
}
trap cleanup EXIT
cleanup

# ── Step 1: Check Qubitcoin binary ──────────────────────────────────
echo "=== Step 1: Checking qubitcoind binary ==="
QUBITCOIND="./target/release/qubitcoind"
if [[ ! -x "$QUBITCOIND" ]]; then
    echo "  Binary not found, building..."
    # Use full path to cargo in case we're running under sudo
    CARGO="${CARGO:-$(which cargo 2>/dev/null || echo "$HOME/.cargo/bin/cargo")}"
    $CARGO build --release -p qubitcoind 2>&1 | tail -5
fi
if [[ ! -x "$QUBITCOIND" ]]; then
    echo "ERROR: qubitcoind binary not found at $QUBITCOIND"
    echo "  Run 'cargo build --release -p qubitcoind' first."
    exit 1
fi
echo "  Binary: $QUBITCOIND"

# ── Step 2: Create Docker network ──────────────────────────────────
echo "=== Step 2: Creating Docker network ==="
docker network create regtest-net 2>/dev/null || true

# ── Step 3: Launch Bitcoin Core node-A (miner) ─────────────────────
echo "=== Step 3: Launching Bitcoin Core node-A (miner) ==="
docker run -d --name btc-node-a \
    --network=host \
    --entrypoint bitcoind \
    bitcoin/bitcoin:latest \
    -regtest -server=1 -listen=1 \
    -rpcbind=0.0.0.0 -rpcallowip=0.0.0.0/0 \
    -rpcuser=test -rpcpassword=test \
    -port=18444 -rpcport=18443 \
    -v2transport=0 -dnsseed=0 -fixedseeds=0 \
    -printtoconsole=1 -debug=net -debug=mempoolrej

echo "  Waiting for node-A to start..."
for i in $(seq 1 30); do
    if docker exec btc-node-a bitcoin-cli -regtest -rpcuser=test -rpcpassword=test getblockchaininfo >/dev/null 2>&1; then
        echo "  node-A is ready (attempt $i)"
        break
    fi
    sleep 1
done

# Verify node-A is actually running
docker exec btc-node-a bitcoin-cli -regtest -rpcuser=test -rpcpassword=test getblockchaininfo \
    | python3 -c "import sys,json; d=json.load(sys.stdin); print(f'  Chain: {d[\"chain\"]}, blocks: {d[\"blocks\"]}')"

# ── Step 4: Mine 110 blocks ────────────────────────────────────────
echo "=== Step 4: Mining 110 blocks ==="
docker exec btc-node-a bitcoin-cli -regtest -rpcuser=test -rpcpassword=test createwallet "miner" >/dev/null 2>&1 || true
ADDR=$(docker exec btc-node-a bitcoin-cli -regtest -rpcuser=test -rpcpassword=test getnewaddress)
docker exec btc-node-a bitcoin-cli -regtest -rpcuser=test -rpcpassword=test generatetoaddress 110 "$ADDR" >/dev/null
BLOCKS=$(docker exec btc-node-a bitcoin-cli -regtest -rpcuser=test -rpcpassword=test getblockcount)
echo "  Mined blocks, current height: $BLOCKS"

# ── Step 5: Baseline capture (BTC node-B -> node-A) ────────────────
if [[ "$QUICK" == false ]]; then
    echo "=== Step 5: Baseline BTC-to-BTC capture ==="

    # Start tcpdump for baseline
    sudo tcpdump -i any -w "$PCAP_DIR/baseline-btc-btc.pcap" -s 0 "tcp port 18444" &
    TCPDUMP_PID=$!
    sleep 1

    # Launch node-B connecting to node-A
    docker run -d --name btc-node-b \
        --network=host \
        --entrypoint bitcoind \
        bitcoin/bitcoin:latest \
        -regtest -server=1 -listen=0 \
        -rpcuser=test -rpcpassword=test \
        -port=18445 -rpcport=18446 \
        -v2transport=0 -dnsseed=0 -fixedseeds=0 \
        -connect=127.0.0.1:18444 \
        -printtoconsole=1 -debug=net

    echo "  Waiting for node-B to sync headers..."
    for i in $(seq 1 30); do
        B_BLOCKS=$(docker exec btc-node-b bitcoin-cli -regtest -rpcuser=test -rpcpassword=test getblockchaininfo 2>/dev/null | python3 -c "import sys,json; print(json.load(sys.stdin).get('headers',0))" 2>/dev/null || echo "0")
        if [[ "$B_BLOCKS" -ge 110 ]]; then
            echo "  node-B synced: $B_BLOCKS headers"
            break
        fi
        echo "  node-B headers: $B_BLOCKS (attempt $i)"
        sleep 2
    done

    # Save node-A logs for baseline
    docker logs btc-node-a > "$LOG_DIR/node-a-baseline.log" 2>&1
    docker logs btc-node-b > "$LOG_DIR/node-b-baseline.log" 2>&1

    # Stop tcpdump and node-B
    sleep 2
    sudo kill $TCPDUMP_PID 2>/dev/null || true
    wait $TCPDUMP_PID 2>/dev/null || true
    docker stop btc-node-b >/dev/null 2>&1 || true
    docker rm btc-node-b >/dev/null 2>&1 || true

    echo "  Baseline pcap: $PCAP_DIR/baseline-btc-btc.pcap"
    echo "  Baseline logs: $LOG_DIR/node-a-baseline.log, $LOG_DIR/node-b-baseline.log"

    # Analyze baseline
    echo ""
    echo "=== Baseline Analysis ==="
    echo "  node-A getheaders/headers log entries:"
    grep -i "getheaders\|headers\|misbehav\|disconnect\|reject" "$LOG_DIR/node-a-baseline.log" | head -20 || echo "  (none found)"
    echo ""
else
    echo "=== Step 5: Skipped (--quick mode) ==="
fi

# ── Step 6: Qubitcoin capture ───────────────────────────────────────
echo "=== Step 6: Qubitcoin -> Bitcoin Core capture ==="

# Start tcpdump for qubitcoin
sudo tcpdump -i any -w "$PCAP_DIR/qubitcoin-btc.pcap" -s 0 "tcp port 18444" &
TCPDUMP_PID=$!
sleep 1

# Create temp datadir for qubitcoin
QDIR=$(mktemp -d /tmp/qubitcoin-regtest.XXXXX)

echo "  Starting qubitcoind (regtest, connect=127.0.0.1:18444)..."
$QUBITCOIND \
    -regtest \
    -connect=127.0.0.1:18444 \
    -port=18555 \
    -listen=0 \
    -loglevel=debug \
    -datadir="$QDIR" \
    > "$LOG_DIR/qubitcoind.log" 2>&1 &
QUBITCOIN_PID=$!

echo "  Qubitcoind PID: $QUBITCOIN_PID"
echo "  Waiting for handshake and getheaders exchange..."

# Wait up to 30 seconds for qubitcoin to do its thing
HEADERS_RECEIVED=false
for i in $(seq 1 30); do
    sleep 1
    if grep -q "received headers" "$LOG_DIR/qubitcoind.log" 2>/dev/null; then
        HEADERS_RECEIVED=true
        echo "  Headers received! (after ${i}s)"
        # Give it a moment to process all headers
        sleep 3
        break
    fi
    # Also check if it at least sent getheaders
    if [[ $i -eq 5 ]]; then
        echo "  Checking progress at 5s..."
        grep -i "handshake\|getheaders\|header\|error\|disconnect" "$LOG_DIR/qubitcoind.log" 2>/dev/null | tail -5 || echo "    (no relevant logs yet)"
    fi
    if [[ $i -eq 15 ]]; then
        echo "  Checking progress at 15s..."
        grep -i "handshake\|getheaders\|header\|error\|disconnect" "$LOG_DIR/qubitcoind.log" 2>/dev/null | tail -10 || echo "    (no relevant logs yet)"
    fi
done

# Stop qubitcoind
kill $QUBITCOIN_PID 2>/dev/null || true
wait $QUBITCOIN_PID 2>/dev/null || true

# Stop tcpdump
sleep 1
sudo kill $TCPDUMP_PID 2>/dev/null || true
wait $TCPDUMP_PID 2>/dev/null || true

# Save node-A logs from qubitcoin phase
docker logs btc-node-a > "$LOG_DIR/node-a-qubitcoin.log" 2>&1

echo ""
echo "=== Qubitcoin Results ==="
echo "  Qubitcoin pcap: $PCAP_DIR/qubitcoin-btc.pcap"
echo "  Qubitcoin log: $LOG_DIR/qubitcoind.log"
echo ""

echo "--- Qubitcoin log (relevant lines) ---"
grep -i "handshake\|getheaders\|header\|error\|disconnect\|version\|verack\|connect\|sent\|received\|bad" "$LOG_DIR/qubitcoind.log" 2>/dev/null | head -40 || echo "(no relevant logs)"
echo ""

echo "--- node-A log (qubitcoin connection) ---"
grep -i "getheaders\|headers\|misbehav\|disconnect\|reject\|version\|Added connection\|receive\|socket" "$LOG_DIR/node-a-qubitcoin.log" 2>/dev/null | tail -30 || echo "(no relevant logs)"
echo ""

# ── Step 7: Compare pcaps ──────────────────────────────────────────
echo "=== Step 7: Pcap Analysis ==="
if [[ -f "$PCAP_DIR/qubitcoin-btc.pcap" ]]; then
    python3 test-harness/compare_getheaders.py \
        "$PCAP_DIR/qubitcoin-btc.pcap" \
        ${QUICK:+"--baseline"} ${QUICK:+"$PCAP_DIR/baseline-btc-btc.pcap"} \
        2>&1 || echo "  (comparison script failed)"
fi

# ── Summary ─────────────────────────────────────────────────────────
echo ""
echo "=== Summary ==="
if [[ "$HEADERS_RECEIVED" == true ]]; then
    HCOUNT=$(grep -c "received headers" "$LOG_DIR/qubitcoind.log" 2>/dev/null || echo "0")
    echo "  SUCCESS: Qubitcoin received headers ($HCOUNT header message(s))"
    # Check total header count
    grep "total_headers\|header_chain_len\|header sync\|header download" "$LOG_DIR/qubitcoind.log" 2>/dev/null | tail -5
else
    echo "  FAILURE: Qubitcoin did NOT receive headers within 30 seconds"
    echo ""
    echo "  Debug hints:"
    echo "    1. Check $LOG_DIR/qubitcoind.log for errors"
    echo "    2. Check $LOG_DIR/node-a-qubitcoin.log for Bitcoin Core side"
    echo "    3. Run: python3 test-harness/compare_getheaders.py $PCAP_DIR/qubitcoin-btc.pcap"
    echo "    4. Run: tcpdump -r $PCAP_DIR/qubitcoin-btc.pcap -X | head -100"
fi

echo ""
echo "  All logs in: $LOG_DIR/"
echo "  All pcaps in: $PCAP_DIR/"
echo "  Cleanup: docker stop btc-node-a; docker rm btc-node-a; docker network rm regtest-net"
