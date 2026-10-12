#!/usr/bin/env python3
"""End-to-end mining smoke test against a live regtest qubitcoind.

Starts a throwaway regtest node (temp datadir, random RPC credentials) and
drives it the way pool software does:

  1. generatetoaddress to a bech32 P2WSH(OP_TRUE) address
  2. sendrawtransaction + mining it (coinbase = subsidy + fees)
  3. getblocktemplate -> build the block in Python from the template alone
     -> BIP23 proposal -> submitblock; duplicate; long poll; -blocknotify;
     getblockheader; prioritisetransaction ordering
  4. testmempoolaccept + submitpackage (0-fee parent + CPFP child)
  5. a 1-deep reorg through submitblock side branches: the disconnected
     block's transaction returns to the mempool; ZMQ publishes D/C
     sequence events and hashblock for the new tip (needs pyzmq)
  6. RPC transport: batch requests, JSON-RPC 1.0 HTTP status codes

Usage:
    python3 test-harness/mining_smoke.py path/to/qubitcoind [--keep]

Requires only the Python standard library; ZMQ checks run when `zmq`
(pyzmq) is importable and are skipped otherwise.
"""
import base64
import hashlib
import json
import os
import secrets
import shutil
import socket
import struct
import subprocess
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.request

try:
    import zmq  # type: ignore
except ImportError:  # pragma: no cover
    zmq = None


# --------------------------------------------------------------------------
# Encoding helpers
# --------------------------------------------------------------------------

CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"


def _polymod(values):
    gen = [0x3B6A57B2, 0x26508E6D, 0x1EA119FA, 0x3D4233DD, 0x2A1462B3]
    chk = 1
    for v in values:
        top = chk >> 25
        chk = (chk & 0x1FFFFFF) << 5 ^ v
        for i in range(5):
            chk ^= gen[i] if ((top >> i) & 1) else 0
    return chk


def bech32_encode(hrp, witver, program):
    """BIP173 (v0) / BIP350 (v1+) segwit address."""
    data, acc, bits = [witver], 0, 0
    for b in program:
        acc = (acc << 8) | b
        bits += 8
        while bits >= 5:
            bits -= 5
            data.append((acc >> bits) & 31)
    if bits:
        data.append((acc << (5 - bits)) & 31)
    const = 1 if witver == 0 else 0x2BC830A3
    hrp_exp = [ord(c) >> 5 for c in hrp] + [0] + [ord(c) & 31 for c in hrp]
    pm = _polymod(hrp_exp + data + [0] * 6) ^ const
    checksum = [(pm >> 5 * (5 - i)) & 31 for i in range(6)]
    return hrp + "1" + "".join(CHARSET[d] for d in data + checksum)


def varint(n):
    if n < 0xFD:
        return bytes([n])
    if n <= 0xFFFF:
        return b"\xfd" + struct.pack("<H", n)
    return b"\xfe" + struct.pack("<I", n)


def dsha(b):
    return hashlib.sha256(hashlib.sha256(b).digest()).digest()


WITNESS_SCRIPT = b"\x51"  # OP_TRUE
WSH_SPK = b"\x00\x20" + hashlib.sha256(WITNESS_SCRIPT).digest()
ADDRESS = bech32_encode("bcrt", 0, hashlib.sha256(WITNESS_SCRIPT).digest())


def spend(prev_txid, vout, value, fee, version=2):
    """Spend a P2WSH(OP_TRUE) output into one P2WSH(OP_TRUE) output.
    Returns (hex, txid)."""
    ins = bytes.fromhex(prev_txid)[::-1] + struct.pack("<I", vout) + b"\x00" + struct.pack("<I", 0xFFFFFFFF)
    outs = struct.pack("<q", value - fee) + varint(len(WSH_SPK)) + WSH_SPK
    base = struct.pack("<I", version) + b"\x01" + ins + b"\x01" + outs
    wit = b"\x01" + varint(len(WITNESS_SCRIPT)) + WITNESS_SCRIPT
    full = struct.pack("<I", version) + b"\x00\x01" + b"\x01" + ins + b"\x01" + outs + wit + struct.pack("<I", 0)
    return full.hex(), dsha(base + struct.pack("<I", 0))[::-1].hex()


def script_num(n):
    out = bytearray()
    while n:
        out.append(n & 0xFF)
        n >>= 8
    if out and out[-1] & 0x80:
        out.append(0)
    return bytes(out)


def build_block(t, extranonce, txs=None, prev=None, height=None, value=None, commitment=None, curtime=None):
    """Build and solve a block from template fields (pool-style)."""
    txs = t["transactions"] if txs is None else txs
    h = t["height"] if height is None else height
    hp = bytes([0x50 + h]) if 1 <= h <= 16 else bytes([len(script_num(h))]) + script_num(h)
    sig = hp + bytes([len(extranonce)]) + extranonce
    outs = [(t["coinbasevalue"] if value is None else value, WSH_SPK)]
    commit = t["default_witness_commitment"] if commitment is None else commitment
    outs.append((0, bytes.fromhex(commit)))
    vin = b"\x00" * 32 + struct.pack("<I", 0xFFFFFFFF) + varint(len(sig)) + sig + struct.pack("<I", 0xFFFFFFFF)
    vout = varint(len(outs)) + b"".join(struct.pack("<q", v) + varint(len(s)) + s for v, s in outs)
    nonwit = struct.pack("<I", 1) + b"\x01" + vin + vout + struct.pack("<I", 0)
    wit = struct.pack("<I", 1) + b"\x00\x01\x01" + vin + vout + b"\x01\x20" + b"\x00" * 32 + struct.pack("<I", 0)
    hashes = [dsha(nonwit)] + [bytes.fromhex(x["txid"])[::-1] for x in txs]
    while len(hashes) > 1:
        if len(hashes) % 2:
            hashes.append(hashes[-1])
        hashes = [dsha(hashes[i] + hashes[i + 1]) for i in range(0, len(hashes), 2)]
    prev = t["previousblockhash"] if prev is None else prev
    ctime = t["curtime"] if curtime is None else curtime
    target = int(t["target"], 16)

    def header(nonce):
        return (struct.pack("<i", t["version"]) + bytes.fromhex(prev)[::-1] + hashes[0]
                + struct.pack("<III", ctime, int(t["bits"], 16), nonce))

    nonce = 0
    while int.from_bytes(dsha(header(nonce))[::-1], "big") > target:
        nonce += 1
    hdr = header(nonce)
    body = wit + b"".join(bytes.fromhex(x["data"]) for x in txs)
    return (hdr + varint(1 + len(txs)) + body).hex(), dsha(hdr)[::-1].hex()


def empty_commitment():
    """default_witness_commitment of a block holding only the coinbase."""
    return "6a24aa21a9ed" + dsha(b"\x00" * 64).hex()


def coinbase_value(block_hex):
    b = bytes.fromhex(block_hex)
    p = 81 + 4
    if b[p] == 0 and b[p + 1] == 1:
        p += 2
    p += 1 + 36
    sl = b[p]
    p += 1 + sl + 4 + 1
    return struct.unpack("<q", b[p:p + 8])[0]


def free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


# --------------------------------------------------------------------------
# Node
# --------------------------------------------------------------------------

class Node:
    def __init__(self, binary, keep=False):
        self.dir = tempfile.mkdtemp(prefix="qbtc-mining-smoke-")
        self.keep = keep
        self.user, self.password = "smoke", secrets.token_hex(16)
        self.port = free_port()
        self.zmq_addr = "tcp://127.0.0.1:%d" % free_port()
        self.notify_log = os.path.join(self.dir, "blocknotify.log")
        args = [binary, "-regtest", "-datadir=" + self.dir, "-rpcport=%d" % self.port,
                "-port=%d" % free_port(), "-listen=0", "-rpcuser=" + self.user,
                "-rpcpassword=" + self.password, "-blocknotify=echo %s >> " + self.notify_log]
        for topic in ("hashblock", "hashtx", "rawblock", "rawtx", "sequence"):
            args.append("-zmqpub%s=%s" % (topic, self.zmq_addr))
        self.proc = subprocess.Popen(args, stdout=open(os.path.join(self.dir, "debug.log"), "w"),
                                     stderr=subprocess.STDOUT)
        for _ in range(200):
            try:
                self.call("getblockcount")
                return
            except Exception:
                time.sleep(0.1)
        raise RuntimeError("qubitcoind did not start; see %s/debug.log" % self.dir)

    def post(self, payload):
        auth = base64.b64encode(("%s:%s" % (self.user, self.password)).encode()).decode()
        req = urllib.request.Request("http://127.0.0.1:%d/" % self.port, json.dumps(payload).encode(),
                                     {"Authorization": "Basic " + auth, "Content-Type": "application/json"})
        try:
            with urllib.request.urlopen(req, timeout=300) as r:
                return r.status, json.loads(r.read() or b"null")
        except urllib.error.HTTPError as e:
            return e.code, json.loads(e.read() or b"null")

    def rpc(self, method, *params):
        """JSON-RPC 1.0 call (as ckpool sends); returns the reply object."""
        return self.post({"method": method, "params": list(params), "id": 1})[1]

    def call(self, method, *params):
        r = self.rpc(method, *params)
        if r.get("error"):
            raise RuntimeError("%s: %s" % (method, r["error"]))
        return r["result"]

    def stop(self):
        self.proc.terminate()
        self.proc.wait()
        if not self.keep:
            shutil.rmtree(self.dir, ignore_errors=True)


def check(cond, msg):
    if not cond:
        raise AssertionError(msg)


def main():
    if len(sys.argv) < 2:
        print(__doc__)
        sys.exit(2)
    node = Node(sys.argv[1], keep="--keep" in sys.argv)
    sub = None
    try:
        if zmq is not None:
            sub = zmq.Context().socket(zmq.SUB)
            sub.setsockopt(zmq.RCVTIMEO, 3000)
            sub.connect(node.zmq_addr)
            sub.setsockopt_string(zmq.SUBSCRIBE, "")
            time.sleep(0.5)

        # 1. generatetoaddress.
        check(node.rpc("generatetoaddress", 1, "notanaddress")["error"]["code"] == -5, "invalid address rejected")
        hashes = node.call("generatetoaddress", 101, ADDRESS)
        check(len(hashes) == 101, "101 blocks")
        cbs = [node.call("getblock", h, 1)["tx"][0] for h in hashes[:4]]
        value = 50_0000_0000

        # 2. sendrawtransaction, mined with its fee.
        raw, txid = spend(cbs[0], 0, value, 12_345)
        check(node.call("sendrawtransaction", raw) == txid, "sendrawtransaction")
        h = node.call("generatetoaddress", 1, ADDRESS)[0]
        check(node.call("getblock", h, 1)["tx"][1] == txid, "mempool tx mined")
        check(coinbase_value(node.call("getblock", h, 0)) == value + 12_345, "coinbase = subsidy + fee")

        # 3. GBT -> build -> proposal -> submitblock.
        a, a_id = spend(cbs[1], 0, value, 1_000)
        b, b_id = spend(a_id, 0, value - 1_000, 30_000)
        c, c_id = spend(cbs[2], 0, value, 5_000)
        for x in (a, b, c):
            node.call("sendrawtransaction", x)
        check(node.call("prioritisetransaction", c_id, 0, 100_000) is True, "prioritise")
        reply = node.rpc("getblocktemplate", {"rules": ["segwit"]})
        check("error" in reply and reply["error"] is None, "1.0 reply carries error: null")
        t = reply["result"]
        check([x["txid"] for x in t["transactions"]] == [c_id, a_id, b_id], "prioritised, then CPFP pair")
        check(t["transactions"][2]["depends"] == [2], "depends")
        fees = sum(x["fee"] for x in t["transactions"])
        check(t["coinbasevalue"] == value + fees, "coinbasevalue")

        lp = {}
        th = threading.Thread(target=lambda: lp.update(t=node.call(
            "getblocktemplate", {"rules": ["segwit"], "longpollid": t["longpollid"]})))
        th.start()
        time.sleep(0.5)
        check(th.is_alive(), "long poll waits")
        blk, bhash = build_block(t, b"smoke")
        check(node.call("getblocktemplate", {"mode": "proposal", "data": blk}) is None, "proposal")
        check(node.rpc("submitblock", blk) == {"result": None, "error": None, "id": 1}, "submitblock null")
        check(node.call("getbestblockhash") == bhash, "tip advanced")
        check(coinbase_value(node.call("getblock", bhash, 0)) == value + fees, "coinbase pays fees")
        check(node.call("submitblock", blk) == "duplicate", "duplicate")
        hdr = node.call("getblockheader", bhash)
        check(hdr["confirmations"] == 1 and hdr["nTx"] == 4, "getblockheader")
        th.join(10)
        check(not th.is_alive() and lp["t"]["previousblockhash"] == bhash, "long poll returned on new tip")
        check(node.call("getprioritisedtransactions") == {}, "delta cleared once mined")

        # 4. testmempoolaccept + submitpackage.
        p, p_id = spend(cbs[3], 0, value, 0)
        k, k_id = spend(p_id, 0, value, 20_000)
        r = node.call("testmempoolaccept", [p, k])
        check([x["allowed"] for x in r] == [True, True], "testmempoolaccept package")
        r = node.call("submitpackage", [p, k])
        check(r["package_msg"] == "success", "submitpackage")
        check(set(node.call("getrawmempool")) == {p_id, k_id}, "package in mempool")
        node.call("generatetoaddress", 1, ADDRESS)

        # 5. Reorg through submitblock side branches.
        cb5 = node.call("getblock", hashes[4], 1)["tx"][0]
        x, x_id = spend(cb5, 0, value, 2_000)
        node.call("sendrawtransaction", x)
        t = node.call("getblocktemplate", {"rules": ["segwit"]})
        check([y["txid"] for y in t["transactions"]] == [x_id], "template holds x")
        if sub is not None:
            while True:
                try:
                    sub.recv_multipart()
                except zmq.Again:
                    break
        blk_a, hash_a = build_block(t, b"branch-a")
        check(node.call("submitblock", blk_a) is None, "A connects")
        subsidy = t["coinbasevalue"] - 2_000
        blk_b, hash_b = build_block(t, b"branch-b", txs=[], value=subsidy, commitment=empty_commitment())
        check(node.call("submitblock", blk_b) == "inconclusive", "B stored as side branch")
        t2 = dict(t, previousblockhash=hash_b, height=t["height"] + 1)
        blk_b2, hash_b2 = build_block(t2, b"branch-b2", txs=[], value=subsidy,
                                      commitment=empty_commitment(), curtime=t["curtime"] + 1)
        check(node.call("submitblock", blk_b2) is None, "B2 reorganises")
        check(node.call("getbestblockhash") == hash_b2, "tip is B2")
        check(x_id in node.call("getrawmempool"), "x back in the mempool")
        if sub is not None:
            msgs = []
            while True:
                try:
                    msgs.append(sub.recv_multipart())
                except zmq.Again:
                    break
            seq = [(m[1][:32].hex(), m[1][32:33]) for m in msgs if m[0] == b"sequence"]
            check((hash_a, b"D") in seq, "ZMQ D for A")
            check((hash_b, b"C") in seq and (hash_b2, b"C") in seq, "ZMQ C for B, B2")
            check((x_id, b"A") in seq, "ZMQ A for the re-added tx")
            hb = [m[1].hex() for m in msgs if m[0] == b"hashblock"]
            check(hb[-1] == hash_b2, "hashblock for the new tip")

        # 6. Transport.
        st, batch = node.post([{"method": "getblockcount", "id": 1},
                               {"jsonrpc": "2.0", "method": "getbestblockhash", "id": 2},
                               {"method": "nosuchmethod", "id": 3}])
        check(st == 200 and len(batch) == 3 and batch[2]["error"]["code"] == -32601, "batch")
        st, _ = node.post({"method": "nosuchmethod", "id": 4})
        check(st == 404, "1.0 method-not-found is HTTP 404")
        st, _ = node.post({"jsonrpc": "2.0", "method": "nosuchmethod", "id": 5})
        check(st == 200, "2.0 errors are HTTP 200")

        time.sleep(1.0)
        notified = open(node.notify_log).read().split()
        check(hash_b2 in notified, "-blocknotify ran")
        print("mining smoke OK%s" % ("" if sub is not None else " (ZMQ checks skipped: no pyzmq)"))
    finally:
        node.stop()


if __name__ == "__main__":
    main()
