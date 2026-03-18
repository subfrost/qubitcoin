/**
 * DevnetTestHarness — in-process JSON-RPC server for integration tests.
 *
 * Wraps the qubitcoin-web-sys DevnetServer WASM export and provides:
 * - Full alkanes RPC protocol (btc_*, alkanes_*, esplora_*, etc.)
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
export interface DevnetTestHarnessOptions {
    /** Compiled alkanes indexer WASM module bytes. */
    alkanesWasm: Uint8Array;
    /** Optional compiled esplora indexer WASM module bytes. */
    esploraWasm?: Uint8Array;
    /** 32-byte secret key for coinbase. Defaults to 0x0101...01. */
    secretKey?: Uint8Array;
    /** URL patterns to intercept. Defaults to localhost:18888. */
    interceptUrls?: string[];
}
export declare class DevnetTestHarness {
    private server;
    private originalFetch;
    private interceptUrls;
    private constructor();
    /**
     * Create a new devnet test harness.
     *
     * Loads the WASM modules and creates the in-process chain + indexers.
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
     * Process a JSON-RPC request and return the response.
     *
     * This is the low-level entry point — use the fetch interceptor for
     * seamless integration with WebProvider.
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
    private handleFetchRequest;
}
//# sourceMappingURL=devnet-server.d.ts.map