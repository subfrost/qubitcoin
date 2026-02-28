#!/usr/bin/env python3
"""
compare_getheaders.py -- Parse Bitcoin P2P messages from pcap files.

Extracts and displays getheaders/headers messages at the byte level,
suitable for comparing Bitcoin Core baseline vs Qubitcoin captures.

Usage:
    python3 compare_getheaders.py <qubitcoin.pcap> [--baseline <baseline.pcap>]
    python3 compare_getheaders.py <capture.pcap>  # single file analysis
"""

import struct
import sys
import os

# Bitcoin regtest magic
REGTEST_MAGIC = b'\xfa\xbf\xb5\xda'
MAINNET_MAGIC = b'\xf9\xbe\xb4\xd9'
TESTNET_MAGIC = b'\x0b\x11\x09\x07'

ALL_MAGICS = [REGTEST_MAGIC, MAINNET_MAGIC, TESTNET_MAGIC]

def read_pcap(filename):
    """Read a pcap file and return all TCP payload bytes concatenated per stream."""
    with open(filename, 'rb') as f:
        # pcap global header: 24 bytes
        global_hdr = f.read(24)
        if len(global_hdr) < 24:
            print(f"ERROR: {filename} is too small for a pcap file")
            return b''

        magic = struct.unpack('<I', global_hdr[0:4])[0]
        if magic == 0xa1b2c3d4:
            endian = '<'
        elif magic == 0xd4c3b2a1:
            endian = '>'
        else:
            print(f"ERROR: Not a valid pcap file (magic: 0x{magic:08x})")
            return b''

        # Read link-layer header type
        # global header: magic(4) + version_major(2) + version_minor(2) + thiszone(4) + sigfigs(4) + snaplen(4) + network(4)
        network = struct.unpack(endian + 'I', global_hdr[20:24])[0]

        all_data = b''
        pkt_count = 0

        while True:
            # Packet header: ts_sec(4) + ts_usec(4) + incl_len(4) + orig_len(4)
            pkt_hdr = f.read(16)
            if len(pkt_hdr) < 16:
                break

            incl_len = struct.unpack(endian + 'I', pkt_hdr[8:12])[0]
            pkt_data = f.read(incl_len)
            if len(pkt_data) < incl_len:
                break
            pkt_count += 1

            # Extract TCP payload
            tcp_payload = extract_tcp_payload(pkt_data, network)
            if tcp_payload:
                all_data += tcp_payload

        print(f"  Read {pkt_count} packets, {len(all_data)} bytes of TCP payload from {filename}")
        return all_data


def extract_tcp_payload(pkt_data, link_type):
    """Extract TCP payload from a packet, handling various link layers."""
    offset = 0

    # Link layer
    if link_type == 1:  # Ethernet
        if len(pkt_data) < 14:
            return None
        ethertype = struct.unpack('>H', pkt_data[12:14])[0]
        offset = 14
        # Handle VLAN tags
        while ethertype in (0x8100, 0x88a8):
            offset += 4
            if offset + 2 > len(pkt_data):
                return None
            ethertype = struct.unpack('>H', pkt_data[offset-2:offset])[0]
        if ethertype != 0x0800:  # Not IPv4
            return None
    elif link_type == 113:  # Linux cooked capture (SLL)
        if len(pkt_data) < 16:
            return None
        proto = struct.unpack('>H', pkt_data[14:16])[0]
        offset = 16
        if proto != 0x0800:
            return None
    elif link_type == 276:  # Linux cooked capture v2 (SLL2)
        if len(pkt_data) < 20:
            return None
        proto = struct.unpack('>H', pkt_data[0:2])[0]
        offset = 20
        if proto != 0x0800:
            return None
    else:
        return None

    # IPv4 header
    if offset + 20 > len(pkt_data):
        return None
    ip_ver_ihl = pkt_data[offset]
    if (ip_ver_ihl >> 4) != 4:
        return None
    ip_hdr_len = (ip_ver_ihl & 0x0f) * 4
    ip_proto = pkt_data[offset + 9]
    if ip_proto != 6:  # Not TCP
        return None

    # TCP header
    tcp_offset = offset + ip_hdr_len
    if tcp_offset + 20 > len(pkt_data):
        return None
    tcp_data_offset = ((pkt_data[tcp_offset + 12] >> 4) * 4)
    payload_start = tcp_offset + tcp_data_offset

    if payload_start >= len(pkt_data):
        return None

    return pkt_data[payload_start:]


def read_varint(data, offset):
    """Read a Bitcoin-style varint. Returns (value, new_offset)."""
    if offset >= len(data):
        return None, offset
    first = data[offset]
    if first < 0xfd:
        return first, offset + 1
    elif first == 0xfd:
        if offset + 3 > len(data):
            return None, offset
        val = struct.unpack_from('<H', data, offset + 1)[0]
        return val, offset + 3
    elif first == 0xfe:
        if offset + 5 > len(data):
            return None, offset
        val = struct.unpack_from('<I', data, offset + 1)[0]
        return val, offset + 5
    else:
        if offset + 9 > len(data):
            return None, offset
        val = struct.unpack_from('<Q', data, offset + 1)[0]
        return val, offset + 9


def find_messages(data, magic_bytes=None):
    """Scan for Bitcoin P2P messages in raw TCP data."""
    messages = []
    pos = 0

    while pos < len(data) - 24:
        # Look for magic bytes
        found_magic = None
        if magic_bytes and data[pos:pos+4] == magic_bytes:
            found_magic = magic_bytes
        else:
            for m in ALL_MAGICS:
                if data[pos:pos+4] == m:
                    found_magic = m
                    break

        if found_magic is None:
            pos += 1
            continue

        # Parse header
        if pos + 24 > len(data):
            break

        command_bytes = data[pos+4:pos+16]
        command = command_bytes.split(b'\x00')[0].decode('ascii', errors='replace')
        payload_size = struct.unpack_from('<I', data, pos + 16)[0]
        checksum = data[pos+20:pos+24]

        # Sanity check payload size
        if payload_size > 32 * 1024 * 1024:
            pos += 1
            continue

        payload_start = pos + 24
        payload_end = payload_start + payload_size

        if payload_end > len(data):
            # Partial message - still record what we have
            messages.append({
                'offset': pos,
                'command': command,
                'payload_size': payload_size,
                'checksum': checksum,
                'payload': data[payload_start:min(payload_end, len(data))],
                'complete': False,
                'magic': found_magic,
            })
            pos = payload_end
            continue

        payload = data[payload_start:payload_end]
        messages.append({
            'offset': pos,
            'command': command,
            'payload_size': payload_size,
            'checksum': checksum,
            'payload': payload,
            'complete': True,
            'magic': found_magic,
        })
        pos = payload_end

    return messages


def parse_version(payload):
    """Parse a version message payload."""
    if len(payload) < 46:
        return {'error': 'too short'}

    result = {}
    result['version'] = struct.unpack_from('<i', payload, 0)[0]
    result['services'] = struct.unpack_from('<Q', payload, 4)[0]
    result['timestamp'] = struct.unpack_from('<q', payload, 12)[0]
    # addr_recv at 20 (26 bytes: 8 services + 16 ip + 2 port)
    result['addr_recv_services'] = struct.unpack_from('<Q', payload, 20)[0]
    result['addr_recv_ip'] = payload[28:44].hex()
    result['addr_recv_port'] = struct.unpack_from('>H', payload, 44)[0]

    if len(payload) >= 72:
        result['addr_from_services'] = struct.unpack_from('<Q', payload, 46)[0]
        result['addr_from_ip'] = payload[54:70].hex()
        result['addr_from_port'] = struct.unpack_from('>H', payload, 70)[0]

    if len(payload) >= 80:
        result['nonce'] = struct.unpack_from('<Q', payload, 72)[0]

    if len(payload) > 80:
        ua_len, ua_off = read_varint(payload, 80)
        if ua_len is not None and ua_off + ua_len <= len(payload):
            result['user_agent'] = payload[ua_off:ua_off+ua_len].decode('utf-8', errors='replace')
            sh_off = ua_off + ua_len
            if sh_off + 4 <= len(payload):
                result['start_height'] = struct.unpack_from('<i', payload, sh_off)[0]
            if sh_off + 5 <= len(payload):
                result['relay'] = payload[sh_off + 4] != 0

    return result


def parse_getheaders(payload):
    """Parse a getheaders/getblocks message payload."""
    if len(payload) < 4:
        return {'error': 'too short'}

    result = {}
    result['version'] = struct.unpack_from('<I', payload, 0)[0]

    count, offset = read_varint(payload, 4)
    if count is None:
        return {'error': 'bad varint'}

    result['hash_count'] = count
    result['locators'] = []

    for i in range(count):
        if offset + 32 > len(payload):
            result['error'] = f'truncated at locator {i}'
            break
        hash_bytes = payload[offset:offset+32]
        result['locators'].append(hash_bytes[::-1].hex())  # Display as big-endian
        offset += 32

    if offset + 32 <= len(payload):
        result['hash_stop'] = payload[offset:offset+32][::-1].hex()
    else:
        result['hash_stop'] = '(missing)'

    result['total_payload_size'] = len(payload)
    result['expected_size'] = 4 + 1 + count * 32 + 32  # simplified for count < 0xfd

    return result


def parse_headers(payload):
    """Parse a headers message payload."""
    if len(payload) == 0:
        return {'count': 0, 'headers': []}

    count, offset = read_varint(payload, 0)
    if count is None:
        return {'error': 'bad varint'}

    result = {'count': count, 'headers': []}

    for i in range(min(count, 5)):  # Only parse first 5
        if offset + 81 > len(payload):
            result['error'] = f'truncated at header {i}'
            break
        hdr_bytes = payload[offset:offset+80]
        # Parse block header fields
        version = struct.unpack_from('<i', hdr_bytes, 0)[0]
        prev_hash = hdr_bytes[4:36][::-1].hex()
        merkle = hdr_bytes[36:68][::-1].hex()
        timestamp = struct.unpack_from('<I', hdr_bytes, 68)[0]
        bits = struct.unpack_from('<I', hdr_bytes, 72)[0]
        nonce = struct.unpack_from('<I', hdr_bytes, 76)[0]
        txn_count = payload[offset+80]

        result['headers'].append({
            'index': i,
            'version': version,
            'prev_hash': prev_hash[:16] + '...',
            'timestamp': timestamp,
            'bits': f'0x{bits:08x}',
            'nonce': nonce,
            'txn_count': txn_count,
        })
        offset += 81

    return result


def display_message(msg, prefix=""):
    """Pretty-print a parsed message."""
    cmd = msg['command']
    size = msg['payload_size']
    complete = msg['complete']
    magic_hex = msg['magic'].hex()

    status = "" if complete else " [INCOMPLETE]"
    print(f"{prefix}[{magic_hex}] {cmd:12s} payload={size:6d} bytes  checksum={msg['checksum'].hex()}{status}")

    payload = msg['payload']

    if cmd == 'version':
        ver = parse_version(payload)
        for k, v in ver.items():
            print(f"{prefix}  {k}: {v}")

    elif cmd in ('getheaders', 'getblocks'):
        gh = parse_getheaders(payload)
        for k, v in gh.items():
            if k == 'locators':
                print(f"{prefix}  locators ({len(v)}):")
                for i, h in enumerate(v):
                    print(f"{prefix}    [{i}] {h}")
            else:
                print(f"{prefix}  {k}: {v}")

        # Also show raw hex for debugging
        print(f"{prefix}  raw_hex ({len(payload)} bytes): {payload.hex()}")

    elif cmd == 'headers':
        hdr = parse_headers(payload)
        print(f"{prefix}  count: {hdr.get('count', '?')}")
        for h in hdr.get('headers', []):
            print(f"{prefix}    [{h['index']}] ver={h['version']} prev={h['prev_hash']} bits={h['bits']} nonce={h['nonce']}")
        if 'error' in hdr:
            print(f"{prefix}  error: {hdr['error']}")

    elif cmd == 'verack':
        print(f"{prefix}  (empty payload)")

    elif cmd in ('ping', 'pong') and len(payload) >= 8:
        nonce = struct.unpack_from('<Q', payload, 0)[0]
        print(f"{prefix}  nonce: {nonce}")

    elif cmd == 'sendheaders':
        print(f"{prefix}  (empty payload)")

    elif cmd == 'sendcmpct' and len(payload) >= 9:
        announce = payload[0] != 0
        version = struct.unpack_from('<Q', payload, 1)[0]
        print(f"{prefix}  announce={announce}, version={version}")

    elif cmd == 'feefilter' and len(payload) >= 8:
        fee = struct.unpack_from('<q', payload, 0)[0]
        print(f"{prefix}  fee: {fee} sat/kvB")

    elif cmd == 'wtxidrelay':
        print(f"{prefix}  (empty payload)")

    elif cmd == 'sendaddrv2':
        print(f"{prefix}  (empty payload)")


def analyze_file(filename, label=""):
    """Analyze all messages in a pcap file."""
    print(f"\n{'='*60}")
    print(f"  Analyzing: {filename}")
    if label:
        print(f"  Label: {label}")
    print(f"{'='*60}")

    data = read_pcap(filename)
    if not data:
        print("  No TCP payload data found.")
        return []

    messages = find_messages(data)
    print(f"  Found {len(messages)} P2P messages\n")

    for msg in messages:
        display_message(msg, prefix="  ")
        print()

    return messages


def compare_getheaders(msgs_a, msgs_b, label_a="Baseline", label_b="Qubitcoin"):
    """Compare getheaders messages between two captures."""
    gh_a = [m for m in msgs_a if m['command'] == 'getheaders']
    gh_b = [m for m in msgs_b if m['command'] == 'getheaders']

    print(f"\n{'='*60}")
    print(f"  Comparing getheaders messages")
    print(f"  {label_a}: {len(gh_a)} getheaders messages")
    print(f"  {label_b}: {len(gh_b)} getheaders messages")
    print(f"{'='*60}\n")

    if not gh_a:
        print(f"  WARNING: No getheaders messages in {label_a} capture")
    if not gh_b:
        print(f"  WARNING: No getheaders messages in {label_b} capture")

    # Compare first getheaders from each
    for i in range(min(len(gh_a), len(gh_b))):
        a = gh_a[i]
        b = gh_b[i]

        print(f"  --- getheaders #{i} comparison ---")
        pa = parse_getheaders(a['payload'])
        pb = parse_getheaders(b['payload'])

        # Compare version
        if pa.get('version') != pb.get('version'):
            print(f"  DIFF version: {label_a}={pa.get('version')} vs {label_b}={pb.get('version')}")
        else:
            print(f"  OK   version: {pa.get('version')}")

        # Compare hash count
        if pa.get('hash_count') != pb.get('hash_count'):
            print(f"  DIFF hash_count: {label_a}={pa.get('hash_count')} vs {label_b}={pb.get('hash_count')}")
        else:
            print(f"  OK   hash_count: {pa.get('hash_count')}")

        # Compare payload size
        if len(a['payload']) != len(b['payload']):
            print(f"  DIFF payload_size: {label_a}={len(a['payload'])} vs {label_b}={len(b['payload'])}")
        else:
            print(f"  OK   payload_size: {len(a['payload'])}")

        # Byte-by-byte diff of payloads
        min_len = min(len(a['payload']), len(b['payload']))
        diffs = []
        for j in range(min_len):
            if a['payload'][j] != b['payload'][j]:
                diffs.append(j)

        if diffs:
            print(f"  DIFF bytes at offsets: {diffs[:20]}{'...' if len(diffs) > 20 else ''}")
            for d in diffs[:10]:
                print(f"    offset {d}: {label_a}=0x{a['payload'][d]:02x} vs {label_b}=0x{b['payload'][d]:02x}")
        else:
            if len(a['payload']) == len(b['payload']):
                print(f"  OK   payloads are identical")
            else:
                print(f"  PARTIAL MATCH: first {min_len} bytes match, but sizes differ")

        print()


def main():
    args = sys.argv[1:]

    if not args or '--help' in args:
        print(__doc__)
        sys.exit(0)

    qubitcoin_pcap = args[0]
    baseline_pcap = None

    if '--baseline' in args:
        idx = args.index('--baseline')
        if idx + 1 < len(args):
            baseline_pcap = args[idx + 1]

    # Analyze qubitcoin capture
    qmsgs = analyze_file(qubitcoin_pcap, "Qubitcoin -> Bitcoin Core")

    # Analyze baseline if provided
    if baseline_pcap and os.path.exists(baseline_pcap):
        bmsgs = analyze_file(baseline_pcap, "Bitcoin Core -> Bitcoin Core (baseline)")
        compare_getheaders(bmsgs, qmsgs)
    else:
        # Just summarize what we found
        gh = [m for m in qmsgs if m['command'] == 'getheaders']
        hdr = [m for m in qmsgs if m['command'] == 'headers']
        ver = [m for m in qmsgs if m['command'] == 'version']
        vak = [m for m in qmsgs if m['command'] == 'verack']

        print(f"\n{'='*60}")
        print(f"  Summary")
        print(f"{'='*60}")
        print(f"  version messages:    {len(ver)}")
        print(f"  verack messages:     {len(vak)}")
        print(f"  getheaders messages: {len(gh)}")
        print(f"  headers messages:    {len(hdr)}")

        if hdr:
            for h in hdr:
                parsed = parse_headers(h['payload'])
                print(f"    headers response: {parsed.get('count', 0)} headers")
        else:
            print(f"\n  WARNING: No headers response received!")
            if gh:
                print(f"  Qubitcoin sent {len(gh)} getheaders but got no headers back.")
                print(f"  This suggests the getheaders payload may be malformed,")
                print(f"  or there's a transport-level issue preventing delivery.")


if __name__ == '__main__':
    main()
