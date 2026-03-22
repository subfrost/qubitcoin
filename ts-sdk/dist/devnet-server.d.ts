/**
 * DevnetTestHarness — in-process JSON-RPC server for integration tests.
 *
 * Wraps the qubitcoin-web-sys DevnetServer WASM export and provides:
 * - Full alkanes RPC protocol (btc_*, alkanes_*, esplora_*, etc.)
 * - Lua script execution via wasmoon (lua_evalscript, lua_evalsaved, etc.)
 * - Auto-indexing through loaded WASM indexer modules
 * - Fetch interceptor for seamless WebProvider integration
 *
 * @example
 * ```ts
 * import { DevnetTestHarness } from '@qubitcoin/sdk';
 *
 * const harness = await DevnetTestHarness.create({
 *   alkanesWasm: await readFile('alkanes.wasm'),
 * });
 *
 * harness.mineBlocks(101);
 * harness.installFetchInterceptor();
 *
 * // Now any fetch() to the RPC endpoint routes to the in-process devnet
 * const resp = await fetch('http://localhost:18888/', {
 *   method: 'POST',
 *   body: JSON.stringify({ jsonrpc: '2.0', method: 'btc_getblockcount', params: [], id: 1 }),
 * });
 * const { result } = await resp.json(); // => 101
 *
 * harness.dispose();
 * ```
 */
/** A tertiary indexer WASM to load into the devnet. */
export interface TertiaryIndexerConfig {
    /** Unique label for this tertiary indexer (e.g., "quspo", "qusprey"). */
    label: string;
    /** Compiled tertiary indexer WASM module bytes. */
    wasm: Uint8Array;
}
export interface DevnetTestHarnessOptions {
    /** Compiled alkanes indexer WASM module bytes. */
    alkanesWasm: Uint8Array;
    /** Optional compiled esplora indexer WASM module bytes. */
    esploraWasm?: Uint8Array;
    /**
     * Optional tertiary indexer WASMs. Tertiary indexers run after secondary
     * indexers and can read their state via __secondary_get host functions.
     */
    tertiaryIndexers?: TertiaryIndexerConfig[];
    /** 32-byte secret key for coinbase. Defaults to 0x0101...01. */
    secretKey?: Uint8Array;
    /** URL patterns to intercept. Defaults to localhost:18888. */
    interceptUrls?: string[];
    /**
     * Path to directory containing Lua scripts (e.g. ~/alkanes-rs/lua/).
     * If provided, scripts are pre-loaded for lua_evalsaved calls.
     * If omitted, tries common paths automatically.
     */
    luaScriptsDir?: string;
}
export declare class DevnetTestHarness {
    private server;
    private originalFetch;
    private interceptUrls;
    private luaRuntime;
    private luaInitPromise;
    private constructor();
    /**
     * Create a new devnet test harness.
     *
     * Loads the WASM modules and creates the in-process chain + indexers.
     * Optionally initializes the Lua runtime for script execution.
     */
    static create(opts: DevnetTestHarnessOptions): Promise<DevnetTestHarness>;
    /** Current chain height. */
    get height(): number;
    /** Current alkanes indexer height. */
    get indexerHeight(): number;
    /** Tip block hash as hex. */
    get tipHashHex(): string;
    /** Mine N empty blocks and auto-index through all indexers. */
    mineBlocks(count: number): void;
    /**
     * Mine a block with extra outputs in the coinbase transaction.
     *
     * This is metaprotocol-agnostic — pass raw TxOut data as hex.
     * Format: repeated [8-byte LE value][2-byte LE script_len][script_bytes]
     *
     * Example: to add a 546-sat P2TR output to coinbase:
     *   const value = Buffer.alloc(8); value.writeBigInt64LE(546n);
     *   const script = bitcoin.address.toOutputScript(addr, network);
     *   const scriptLen = Buffer.alloc(2); scriptLen.writeUInt16LE(script.length);
     *   const hex = Buffer.concat([value, scriptLen, script]).toString('hex');
     *   harness.mineBlockWithCoinbaseOutputs(hex);
     */
    mineBlockWithCoinbaseOutputs(extraOutputsHex: string): void;
    /**
     * Process a JSON-RPC request and return the response.
     *
     * Lua methods (lua_evalscript, lua_evalsaved, etc.) are handled by the
     * wasmoon runtime. All other methods are dispatched to the Rust WASM backend.
     */
    handleRpc(requestJson: string): string;
    /**
     * Install a fetch interceptor that routes JSON-RPC POST requests
     * to the in-process devnet server.
     *
     * After calling this, any `fetch()` to the intercepted URLs will
     * be handled in-process without network access.
     */
    installFetchInterceptor(): void;
    /** Restore the original fetch function. */
    restoreFetch(): void;
    /** Clean up: restore fetch and free WASM resources. */
    dispose(): void;
    /**
     * Initialize the Lua runtime and pre-load known scripts.
     */
    private initLuaRuntime;
    /**
     * Ensure the Lua runtime is initialized before use.
     */
    private ensureLuaRuntime;
    /**
     * Handle a Lua RPC method (evalscript, evalsaved, savescript).
     *
     * Returns JSON-RPC response string, or null if Lua runtime unavailable
     * (caller should fall through to Rust shims).
     */
    private handleLuaRpc;
    private handleFetchRequest;
    /**
     * Resolve a REST-style URL + body into a JSON-RPC method + params.
     *
     * Maps espo data API REST endpoints to the RPC dispatcher's namespace:
     *   /get-all-pools-details    → ammdata.get_pools
     *   /get-all-token-pairs      → ammdata.get_pools
     *   /get-alkanes-by-address   → essentials.get_address_balances
     *   /get-bitcoin-price        → (handled inline)
     *   /get-all-amm-tx-history   → ammdata.get_activity
     */
    private resolveRestMethod;
}
//# sourceMappingURL=devnet-server.d.ts.map