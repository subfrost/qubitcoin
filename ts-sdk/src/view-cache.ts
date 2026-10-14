/**
 * DevnetViewCache — memoizes the two alkanes view reads that dominate devnet
 * test cost, without changing any response a caller can observe.
 *
 * Why: every alkanes view call instantiates a fresh alkanes WASM instance.
 * `protorunesbyoutpoint` grows that instance to ~100 MB (it runs the contract
 * VM for each balance's name/symbol), and app suites ask for the same handful
 * of outpoints hundreds of times. Measured on subfrost-app's devnet suite
 * (e2e-frusd-hub): 639 outpoint views over 110 unique outpoints and 89
 * address views over 2 inputs; caching cut total WASM allocation 68 → 19 GB
 * and that file's runtime 42 → 30 s. Peak RSS is unchanged — this is a
 * throughput/churn win, not a ceiling win.
 *
 * Soundness — the devnet chain only moves forward except through importState:
 *  - `sendrawtransaction(s)` mines immediately (no mempool), so any state
 *    change bumps `height`; there is no invalidateblock/reorg RPC.
 *  - `metashrew_view protorunesbyoutpoint`: an outpoint's balances are fixed
 *    once it is indexed (spending does not rewrite them). We cache ONLY
 *    positive answers — responses whose OutpointResponse carries field 3
 *    (`output`) — because an outpoint that is not indexed yet will become
 *    indexed later. The key includes the block tag (params[2]).
 *  - `alkanes_protorunesbyaddress`: depends on the UTXO set, so entries are
 *    scoped to the current height and dropped as soon as it changes.
 *  - The owner must call `clear()` whenever chain state is replaced
 *    (importState).
 * Errors, batches and every other method pass straight through.
 */

/** OutpointResponse field number that is present only for indexed outpoints. */
const OUTPOINT_RESPONSE_OUTPUT_FIELD = 3;

export interface ViewCacheStats {
  hits: number;
  misses: number;
}

interface RpcRequest {
  method?: unknown;
  params?: unknown;
  id?: unknown;
}

/**
 * True when the hex-encoded protobuf message has top-level field `field`.
 * Walks the wire format without a schema; returns false on malformed input.
 */
export function protobufHasTopLevelField(hex: string, field: number): boolean {
  const h = hex.startsWith('0x') ? hex.slice(2) : hex;
  if (h.length % 2 !== 0 || /[^0-9a-fA-F]/.test(h)) return false;
  const b = new Uint8Array(h.length / 2);
  for (let j = 0; j < b.length; j++) b[j] = parseInt(h.slice(j * 2, j * 2 + 2), 16);

  let i = 0;
  const varint = (): number | null => {
    let v = 0;
    let s = 0;
    while (i < b.length) {
      const c = b[i++];
      v += (c & 0x7f) * 2 ** s;
      if (!(c & 0x80)) return v;
      s += 7;
      if (s > 63) return null;
    }
    return null;
  };

  while (i < b.length) {
    const tag = varint();
    if (tag === null) return false;
    const f = Math.floor(tag / 8);
    const wt = tag % 8;
    if (f === field) return true;
    if (wt === 0) {
      if (varint() === null) return false;
    } else if (wt === 1) {
      i += 8;
    } else if (wt === 2) {
      const len = varint();
      if (len === null) return false;
      i += len;
    } else if (wt === 5) {
      i += 4;
    } else {
      return false;
    }
    if (i > b.length) return false;
  }
  return false;
}

export class DevnetViewCache {
  private outpoints = new Map<string, unknown>();
  private addresses = new Map<string, unknown>();
  private addressHeight = -1;
  private readonly counters: ViewCacheStats = { hits: 0, misses: 0 };

  /** @param height returns the current chain height (scopes address entries). */
  constructor(private readonly height: () => number) {}

  get stats(): ViewCacheStats {
    return { ...this.counters };
  }

  /** Drop everything — call whenever chain state is replaced. */
  clear(): void {
    this.outpoints.clear();
    this.addresses.clear();
    this.addressHeight = -1;
  }

  /**
   * Answer `requestJson` from the cache, or forward it to `next` and keep the
   * result when it is cacheable. Responses are byte-for-byte what `next`
   * would return apart from JSON formatting, with the caller's `id`.
   */
  handle(requestJson: string, next: (json: string) => string): string {
    let req: RpcRequest;
    try {
      req = JSON.parse(requestJson);
    } catch {
      return next(requestJson);
    }
    if (!req || typeof req !== 'object' || Array.isArray(req)) return next(requestJson);
    const params = Array.isArray(req.params) ? req.params : [];

    let store: Map<string, unknown>;
    let key: string;
    let keep: (result: unknown) => boolean;
    if (req.method === 'metashrew_view' && params[0] === 'protorunesbyoutpoint') {
      store = this.outpoints;
      key = `${String(params[1])}|${String(params[2] ?? 'latest')}`;
      keep = (r) => typeof r === 'string' && protobufHasTopLevelField(r, OUTPOINT_RESPONSE_OUTPUT_FIELD);
    } else if (req.method === 'alkanes_protorunesbyaddress') {
      const h = this.height();
      if (h !== this.addressHeight) {
        this.addresses.clear();
        this.addressHeight = h;
      }
      store = this.addresses;
      key = JSON.stringify(params);
      keep = () => true;
    } else {
      return next(requestJson);
    }

    if (store.has(key)) {
      this.counters.hits++;
      return JSON.stringify({ jsonrpc: '2.0', result: store.get(key), id: req.id ?? null });
    }
    this.counters.misses++;
    const out = next(requestJson);
    try {
      const res = JSON.parse(out);
      if (res && !('error' in res && res.error) && 'result' in res && keep(res.result)) {
        store.set(key, res.result);
      }
    } catch {
      // Unparseable response: never cache, return as-is.
    }
    return out;
  }
}
