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
import { LuaRuntime, preloadLuaScripts, saveScript } from './lua-runtime.js';
/** Default secret key (32 bytes of 0x01 — deterministic for testing). */
const DEFAULT_SECRET_KEY = new Uint8Array(32).fill(0x01);
/** Intercepted URL patterns — any POST to these routes to the devnet. */
const DEFAULT_INTERCEPT_URLS = [
    'http://localhost:18888',
    'http://127.0.0.1:18888',
    'http://localhost:8080',
];
/** Methods that are handled by the Lua runtime instead of Rust dispatcher. */
const LUA_METHODS = new Set([
    'lua_evalscript',
    'lua_evalsaved',
    'lua_savescript',
    'sandshrew_evalscript',
    'sandshrew_evalsaved',
    'sandshrew_savescript',
]);
export class DevnetTestHarness {
    server;
    originalFetch = null;
    interceptUrls;
    luaRuntime = null;
    luaInitPromise = null;
    constructor(server, interceptUrls) {
        this.server = server;
        this.interceptUrls = interceptUrls;
    }
    /**
     * Create a new devnet test harness.
     *
     * Loads the WASM modules and creates the in-process chain + indexers.
     * Optionally initializes the Lua runtime for script execution.
     */
    static async create(opts) {
        // Dynamic import and initialize the WASM module
        const wasm = await import('./wasm/qubitcoin_web_sys.js');
        // In Node.js, we need to pass the WASM file path since fetch() may not
        // work for local file:// URLs. Read the .wasm file and pass as bytes.
        if (typeof process !== 'undefined' && process.versions?.node) {
            const { readFileSync } = await import('fs');
            const { fileURLToPath } = await import('url');
            const { dirname, resolve } = await import('path');
            // Resolve relative to the wasm JS file
            const wasmJsUrl = new URL('./wasm/qubitcoin_web_sys_bg.wasm', import.meta.url);
            let wasmPath;
            try {
                wasmPath = fileURLToPath(wasmJsUrl);
            }
            catch {
                // Fallback: resolve from __dirname equivalent
                const thisDir = dirname(fileURLToPath(import.meta.url));
                wasmPath = resolve(thisDir, 'wasm', 'qubitcoin_web_sys_bg.wasm');
            }
            const wasmBytes = readFileSync(wasmPath);
            await wasm.default(wasmBytes);
        }
        else {
            await wasm.default();
        }
        const secretKey = opts.secretKey ?? DEFAULT_SECRET_KEY;
        const esploraArr = opts.esploraWasm
            ? new Uint8Array(opts.esploraWasm)
            : undefined;
        const server = new wasm.DevnetServer(secretKey, opts.alkanesWasm, esploraArr);
        // Load tertiary indexers (run after secondary indexers)
        if (opts.tertiaryIndexers) {
            for (const ti of opts.tertiaryIndexers) {
                server.addTertiary(ti.label, ti.wasm);
            }
        }
        const harness = new DevnetTestHarness(server, opts.interceptUrls ?? DEFAULT_INTERCEPT_URLS);
        // Initialize Lua runtime (non-blocking — will be ready by first use)
        harness.luaInitPromise = harness.initLuaRuntime(opts.luaScriptsDir);
        return harness;
    }
    /** Current chain height. */
    get height() {
        return this.server.height;
    }
    /** Current alkanes indexer height. */
    get indexerHeight() {
        return this.server.indexerHeight;
    }
    /** Tip block hash as hex. */
    get tipHashHex() {
        return this.server.tipHashHex;
    }
    /** Mine N empty blocks and auto-index through all indexers. */
    mineBlocks(count) {
        this.server.mineBlocks(count);
    }
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
    mineBlockWithCoinbaseOutputs(extraOutputsHex) {
        this.server.mineBlockWithCoinbaseOutputs(extraOutputsHex);
    }
    /**
     * Process a JSON-RPC request and return the response.
     *
     * Lua methods (lua_evalscript, lua_evalsaved, etc.) are handled by the
     * wasmoon runtime. All other methods are dispatched to the Rust WASM backend.
     */
    handleRpc(requestJson) {
        // Parse to check if this is a Lua method
        let parsed;
        try {
            parsed = JSON.parse(requestJson);
        }
        catch {
            return this.server.handleRpc(requestJson);
        }
        if (parsed.method && LUA_METHODS.has(parsed.method)) {
            // Lua methods need async execution — we can't do that synchronously.
            // Instead, return a marker that handleFetchRequest will resolve.
            // For direct handleRpc() callers, fall through to Rust shims.
            return this.server.handleRpc(requestJson);
        }
        return this.server.handleRpc(requestJson);
    }
    /**
     * Install a fetch interceptor that routes JSON-RPC POST requests
     * to the in-process devnet server.
     *
     * After calling this, any `fetch()` to the intercepted URLs will
     * be handled in-process without network access.
     */
    installFetchInterceptor() {
        if (this.originalFetch)
            return; // already installed
        this.originalFetch = globalThis.fetch;
        const self = this;
        const interceptedFetch = function (input, init) {
            const url = typeof input === 'string'
                ? input
                : input instanceof URL
                    ? input.toString()
                    : input.url;
            // Only intercept POST requests to matching URLs
            const method = init?.method?.toUpperCase() ?? 'GET';
            if (method === 'POST' && self.interceptUrls.some(u => url.startsWith(u))) {
                return self.handleFetchRequest(url, init);
            }
            // Pass through to original fetch
            return self.originalFetch.call(globalThis, input, init);
        };
        globalThis.fetch = interceptedFetch;
        // Also override window.fetch — the WASM SDK uses window.fetch
        // which is a separate reference set during vitest setup
        if (typeof globalThis !== 'undefined' && globalThis.window) {
            globalThis.window.fetch = interceptedFetch;
        }
    }
    /** Restore the original fetch function. */
    restoreFetch() {
        if (this.originalFetch) {
            globalThis.fetch = this.originalFetch;
            if (typeof globalThis !== 'undefined' && globalThis.window) {
                globalThis.window.fetch = this.originalFetch;
            }
            this.originalFetch = null;
        }
    }
    /** Clean up: restore fetch and free WASM resources. */
    dispose() {
        this.restoreFetch();
        this.luaRuntime = null;
        // DevnetServer is freed when GC collects it (wasm-bindgen destructor)
    }
    // -- Private ---------------------------------------------------------------
    /**
     * Initialize the Lua runtime and pre-load known scripts.
     */
    async initLuaRuntime(luaScriptsDir) {
        try {
            // Create Lua runtime with RPC handler that routes back to this harness
            const rpcHandler = (requestJson) => {
                return this.server.handleRpc(requestJson);
            };
            this.luaRuntime = await LuaRuntime.create(rpcHandler);
            // Pre-load Lua scripts from disk
            if (luaScriptsDir) {
                preloadLuaScripts(luaScriptsDir);
            }
            else {
                // Try common paths
                const { existsSync } = await import('fs');
                const { resolve } = await import('path');
                const home = process.env.HOME || '/home/ubuntu';
                const candidates = [
                    resolve(home, 'alkanes-rs/lua'),
                    resolve(home, 'Documents/GitHub/alkanes-rs/lua'),
                    resolve(process.cwd(), 'node_modules/@alkanes/ts-sdk/lua'),
                ];
                for (const dir of candidates) {
                    if (existsSync(dir)) {
                        preloadLuaScripts(dir);
                        break;
                    }
                }
            }
        }
        catch (err) {
            console.warn('[DevnetTestHarness] Lua runtime init failed, falling back to Rust shims:', err);
            this.luaRuntime = null;
        }
    }
    /**
     * Ensure the Lua runtime is initialized before use.
     */
    async ensureLuaRuntime() {
        if (this.luaInitPromise) {
            await this.luaInitPromise;
            this.luaInitPromise = null;
        }
        return this.luaRuntime;
    }
    /**
     * Handle a Lua RPC method (evalscript, evalsaved, savescript).
     *
     * Returns JSON-RPC response string, or null if Lua runtime unavailable
     * (caller should fall through to Rust shims).
     */
    async handleLuaRpc(method, params, id) {
        const lua = await this.ensureLuaRuntime();
        if (!lua)
            return null;
        const normalizedMethod = method.replace(/^(lua|sandshrew)_/, '');
        if (normalizedMethod === 'savescript') {
            const scriptContent = params[0];
            if (typeof scriptContent !== 'string') {
                return JSON.stringify({
                    jsonrpc: '2.0',
                    error: { code: -32602, message: 'savescript requires script content as first param' },
                    id,
                });
            }
            const hash = saveScript(scriptContent);
            return JSON.stringify({
                jsonrpc: '2.0',
                result: { hash },
                id,
            });
        }
        if (normalizedMethod === 'evalscript') {
            const scriptContent = params[0];
            if (typeof scriptContent !== 'string') {
                return JSON.stringify({
                    jsonrpc: '2.0',
                    error: { code: -32602, message: 'evalscript requires script content as first param' },
                    id,
                });
            }
            const args = params.slice(1);
            const result = await lua.executeScript(scriptContent, args);
            if (result.error) {
                return JSON.stringify({
                    jsonrpc: '2.0',
                    result: {
                        calls: result.calls,
                        returns: null,
                        runtime: result.runtime,
                        error: { code: -1, message: result.error },
                    },
                    id,
                });
            }
            return JSON.stringify({
                jsonrpc: '2.0',
                result: {
                    calls: result.calls,
                    returns: result.returns,
                    runtime: result.runtime,
                },
                id,
            });
        }
        if (normalizedMethod === 'evalsaved') {
            const hash = params[0];
            if (typeof hash !== 'string') {
                return JSON.stringify({
                    jsonrpc: '2.0',
                    error: { code: -32602, message: 'evalsaved requires script hash as first param' },
                    id,
                });
            }
            const args = params.slice(1);
            const result = await lua.executeSaved(hash, args);
            if (result.error) {
                // If script not found, fall through to Rust shims
                if (result.error.includes('Script not found')) {
                    return null;
                }
                return JSON.stringify({
                    jsonrpc: '2.0',
                    result: {
                        calls: result.calls,
                        returns: null,
                        runtime: result.runtime,
                        error: { code: -1, message: result.error },
                    },
                    id,
                });
            }
            return JSON.stringify({
                jsonrpc: '2.0',
                result: {
                    calls: result.calls,
                    returns: result.returns,
                    runtime: result.runtime,
                },
                id,
            });
        }
        return null;
    }
    async handleFetchRequest(url, init) {
        let bodyText;
        if (typeof init?.body === 'string') {
            bodyText = init.body;
        }
        else if (init?.body instanceof ArrayBuffer) {
            bodyText = new TextDecoder().decode(init.body);
        }
        else if (init?.body instanceof Uint8Array) {
            bodyText = new TextDecoder().decode(init.body);
        }
        else {
            // ReadableStream or other — read it
            const resp = new Response(init?.body);
            bodyText = await resp.text();
        }
        try {
            let parsed;
            try {
                parsed = JSON.parse(bodyText);
            }
            catch {
                // Not valid JSON — pass through to Rust
            }
            // If this is a JSON-RPC request (has "method" field), dispatch normally
            if (parsed?.method) {
                // Check for Lua methods first
                if (LUA_METHODS.has(parsed.method)) {
                    const luaResponse = await this.handleLuaRpc(parsed.method, Array.isArray(parsed.params) ? parsed.params : [], parsed.id);
                    if (luaResponse) {
                        return new Response(luaResponse, {
                            status: 200,
                            headers: { 'Content-Type': 'application/json' },
                        });
                    }
                }
                const responseJson = this.server.handleRpc(bodyText);
                return new Response(responseJson, {
                    status: 200,
                    headers: { 'Content-Type': 'application/json' },
                });
            }
            // REST-style request (no "method" field) — route by URL path.
            // The SDK's data API makes REST POSTs like:
            //   POST http://localhost:18888/get-all-pools-details
            //   {"factoryId": {"block": "4", "tx": "65498"}}
            //
            // We translate these to JSON-RPC calls to the dispatcher.
            const restMethod = this.resolveRestMethod(url, parsed);
            if (restMethod) {
                const rpcRequest = JSON.stringify({
                    jsonrpc: '2.0',
                    method: restMethod.method,
                    params: restMethod.params,
                    id: 1,
                });
                const responseJson = this.server.handleRpc(rpcRequest);
                return new Response(responseJson, {
                    status: 200,
                    headers: { 'Content-Type': 'application/json' },
                });
            }
            // Fallback: pass raw body to Rust dispatcher
            const responseJson = this.server.handleRpc(bodyText);
            return new Response(responseJson, {
                status: 200,
                headers: { 'Content-Type': 'application/json' },
            });
        }
        catch (e) {
            const error = e instanceof Error ? e.message : String(e);
            const errorResponse = JSON.stringify({
                jsonrpc: '2.0',
                error: { code: -32603, message: error },
                id: null,
            });
            return new Response(errorResponse, {
                status: 200,
                headers: { 'Content-Type': 'application/json' },
            });
        }
    }
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
    resolveRestMethod(url, body) {
        // Extract the path from the URL
        try {
            const urlObj = new URL(url);
            const path = urlObj.pathname;
            // Match known REST endpoints
            if (path.endsWith('/get-all-pools-details') || path.endsWith('/get-all-token-pairs')) {
                return {
                    method: 'essentials.get_address_outpoints',
                    params: [body || {}],
                };
            }
            if (path.endsWith('/get-alkanes-by-address') || path.endsWith('/get-address-balances')) {
                const address = body?.address || '';
                return {
                    method: 'essentials.get_address_outpoints',
                    params: [{ address }],
                };
            }
            if (path.endsWith('/get-bitcoin-price')) {
                // Return mock price for devnet
                return null; // Handled by catch-all below
            }
            if (path.endsWith('/get-all-amm-tx-history') || path.endsWith('/get-all-address-amm-tx-history')) {
                return {
                    method: 'essentials.get_address_outpoints',
                    params: [body || {}],
                };
            }
        }
        catch {
            // URL parse failed — try path matching on raw string
        }
        return null;
    }
}
//# sourceMappingURL=devnet-server.js.map