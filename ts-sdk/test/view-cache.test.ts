/**
 * Unit tests for DevnetViewCache — pure, no WASM. A fake backend stands in
 * for DevnetServer.handleRpc and counts how often it is reached.
 * Run: npx vitest run test/view-cache.test.ts
 */
import { describe, expect, it } from 'vitest';
import { DevnetViewCache, protobufHasTopLevelField } from '../src/view-cache.js';

/** Encode a protobuf field: tag varint + payload. Only wire types 0 and 2. */
function field(num: number, value: number | number[]): number[] {
  const varint = (n: number) => {
    const out: number[] = [];
    do {
      let c = n % 128;
      n = Math.floor(n / 128);
      if (n > 0) c |= 0x80;
      out.push(c);
    } while (n > 0);
    return out;
  };
  if (typeof value === 'number') return [...varint(num * 8), ...varint(value)];
  return [...varint(num * 8 + 2), ...varint(value.length), ...value];
}
const hex = (bytes: number[]) => '0x' + bytes.map((b) => b.toString(16).padStart(2, '0')).join('');

// OutpointResponse { balances = 1, outpoint = 2, output = 3, height = 4 }
const INDEXED = hex([...field(1, [1, 2, 3]), ...field(2, [9, 9]), ...field(3, [7, 7, 7]), ...field(4, 300)]);
const NOT_INDEXED = hex([...field(2, [9, 9])]);

function fakeBackend(answer: (req: any) => unknown) {
  const calls: string[] = [];
  const next = (json: string) => {
    calls.push(json);
    const req = JSON.parse(json);
    return JSON.stringify({ jsonrpc: '2.0', result: answer(req), id: req.id });
  };
  return { calls, next };
}

const outpointReq = (op: string, id: unknown = 1, tag?: string) =>
  JSON.stringify({ jsonrpc: '2.0', method: 'metashrew_view', params: ['protorunesbyoutpoint', op, ...(tag ? [tag] : [])], id });
const addressReq = (addr: string, id: unknown = 1) =>
  JSON.stringify({ jsonrpc: '2.0', method: 'alkanes_protorunesbyaddress', params: [{ address: addr, protocolTag: '1' }], id });

describe('protobufHasTopLevelField', () => {
  it('finds a present field and skips over earlier ones', () => {
    expect(protobufHasTopLevelField(INDEXED, 3)).toBe(true);
    expect(protobufHasTopLevelField(INDEXED, 4)).toBe(true);
  });
  it('does not see a field that is only present nested inside another', () => {
    const nested = hex(field(2, field(3, [1])));
    expect(protobufHasTopLevelField(nested, 3)).toBe(false);
  });
  it('rejects absent, empty and malformed input', () => {
    expect(protobufHasTopLevelField(NOT_INDEXED, 3)).toBe(false);
    expect(protobufHasTopLevelField('0x', 3)).toBe(false);
    expect(protobufHasTopLevelField('0xzz', 3)).toBe(false);
    expect(protobufHasTopLevelField('0x0', 3)).toBe(false);
    // length-delimited field claiming more bytes than exist
    expect(protobufHasTopLevelField(hex([0x12, 0x10, 0x01]), 3)).toBe(false);
    // unterminated varint
    expect(protobufHasTopLevelField(hex([0x08, 0x80]), 3)).toBe(false);
  });
});

describe('DevnetViewCache — protorunesbyoutpoint', () => {
  it('serves a repeated indexed outpoint from cache with the caller id', () => {
    const { calls, next } = fakeBackend(() => INDEXED);
    const c = new DevnetViewCache(() => 300);
    const first = JSON.parse(c.handle(outpointReq('0xaa', 1), next));
    const second = JSON.parse(c.handle(outpointReq('0xaa', 'abc'), next));
    expect(calls).toHaveLength(1);
    expect(second).toEqual({ ...first, id: 'abc' });
    expect(c.stats).toEqual({ hits: 1, misses: 1 });
  });

  it('never caches a not-yet-indexed outpoint (it can become indexed later)', () => {
    let indexed = false;
    const { calls, next } = fakeBackend(() => (indexed ? INDEXED : NOT_INDEXED));
    const c = new DevnetViewCache(() => 300);
    expect(JSON.parse(c.handle(outpointReq('0xaa'), next)).result).toBe(NOT_INDEXED);
    indexed = true;
    expect(JSON.parse(c.handle(outpointReq('0xaa'), next)).result).toBe(INDEXED);
    expect(calls).toHaveLength(2);
  });

  it('keys on outpoint and block tag', () => {
    const { calls, next } = fakeBackend(() => INDEXED);
    const c = new DevnetViewCache(() => 300);
    c.handle(outpointReq('0xaa'), next);
    c.handle(outpointReq('0xbb'), next);
    c.handle(outpointReq('0xaa', 1, '250'), next);
    c.handle(outpointReq('0xaa', 1, 'latest'), next); // same as no tag
    expect(calls).toHaveLength(3);
  });

  it('survives height changes but not clear()', () => {
    let h = 300;
    const { calls, next } = fakeBackend(() => INDEXED);
    const c = new DevnetViewCache(() => h);
    c.handle(outpointReq('0xaa'), next);
    h = 301;
    c.handle(outpointReq('0xaa'), next);
    expect(calls).toHaveLength(1);
    c.clear();
    c.handle(outpointReq('0xaa'), next);
    expect(calls).toHaveLength(2);
  });

  it('does not cache errors', () => {
    const calls: string[] = [];
    const next = (json: string) => {
      calls.push(json);
      return JSON.stringify({ jsonrpc: '2.0', error: { code: -1, message: 'boom' }, id: 1 });
    };
    const c = new DevnetViewCache(() => 300);
    c.handle(outpointReq('0xaa'), next);
    expect(JSON.parse(c.handle(outpointReq('0xaa'), next)).error.message).toBe('boom');
    expect(calls).toHaveLength(2);
  });
});

describe('DevnetViewCache — alkanes_protorunesbyaddress', () => {
  it('caches within a height and refetches after the height moves', () => {
    let h = 300;
    let balance = 5;
    const { calls, next } = fakeBackend(() => ({ outpoints: [{ balance }] }));
    const c = new DevnetViewCache(() => h);
    expect(JSON.parse(c.handle(addressReq('bcrt1qa'), next)).result.outpoints[0].balance).toBe(5);
    balance = 6; // a new block would be the only way this changes
    expect(JSON.parse(c.handle(addressReq('bcrt1qa'), next)).result.outpoints[0].balance).toBe(5);
    expect(calls).toHaveLength(1);
    h = 301;
    expect(JSON.parse(c.handle(addressReq('bcrt1qa'), next)).result.outpoints[0].balance).toBe(6);
    expect(calls).toHaveLength(2);
  });

  it('keys on params', () => {
    const { calls, next } = fakeBackend((req) => req.params[0].address);
    const c = new DevnetViewCache(() => 300);
    expect(JSON.parse(c.handle(addressReq('bcrt1qa'), next)).result).toBe('bcrt1qa');
    expect(JSON.parse(c.handle(addressReq('bcrt1qb'), next)).result).toBe('bcrt1qb');
    expect(calls).toHaveLength(2);
  });

  it('a cached object cannot be mutated through a returned response', () => {
    const { next } = fakeBackend(() => ({ outpoints: [] }));
    const c = new DevnetViewCache(() => 300);
    c.handle(addressReq('bcrt1qa'), next);
    const r = JSON.parse(c.handle(addressReq('bcrt1qa'), next));
    r.result.outpoints.push('x');
    expect(JSON.parse(c.handle(addressReq('bcrt1qa'), next)).result.outpoints).toEqual([]);
  });
});

describe('DevnetViewCache — pass-through', () => {
  it('forwards other methods, batches and junk untouched, every time', () => {
    const seen: string[] = [];
    const next = (json: string) => {
      seen.push(json);
      return 'RAW';
    };
    const c = new DevnetViewCache(() => 300);
    const inputs = [
      JSON.stringify({ jsonrpc: '2.0', method: 'btc_getblockcount', params: [], id: 1 }),
      JSON.stringify({ jsonrpc: '2.0', method: 'metashrew_view', params: ['simulate', '0x00'], id: 1 }),
      JSON.stringify([JSON.parse(outpointReq('0xaa'))]),
      'not json',
    ];
    for (const s of [...inputs, ...inputs]) expect(c.handle(s, next)).toBe('RAW');
    expect(seen).toEqual([...inputs, ...inputs]);
    expect(c.stats).toEqual({ hits: 0, misses: 0 });
  });
});
