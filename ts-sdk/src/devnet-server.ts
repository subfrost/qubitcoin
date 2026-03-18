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

import type { DevnetServer } from './wasm/qubitcoin_web_sys.js';

/** Default secret key (32 bytes of 0x01 — deterministic for testing). */
const DEFAULT_SECRET_KEY = new Uint8Array(32).fill(0x01);

/** Intercepted URL patterns — any POST to these routes to the devnet. */
const DEFAULT_INTERCEPT_URLS = [
  'http://localhost:18888',
  'http://127.0.0.1:18888',
  'http://localhost:8080',
];

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

export class DevnetTestHarness {
  private server: DevnetServer;
  private originalFetch: typeof globalThis.fetch | null = null;
  private interceptUrls: string[];

  private constructor(
    server: DevnetServer,
    interceptUrls: string[],
  ) {
    this.server = server;
    this.interceptUrls = interceptUrls;
  }

  /**
   * Create a new devnet test harness.
   *
   * Loads the WASM modules and creates the in-process chain + indexers.
   */
  static async create(opts: DevnetTestHarnessOptions): Promise<DevnetTestHarness> {
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
      let wasmPath: string;
      try {
        wasmPath = fileURLToPath(wasmJsUrl);
      } catch {
        // Fallback: resolve from __dirname equivalent
        const thisDir = dirname(fileURLToPath(import.meta.url));
        wasmPath = resolve(thisDir, 'wasm', 'qubitcoin_web_sys_bg.wasm');
      }
      const wasmBytes = readFileSync(wasmPath);
      await wasm.default(wasmBytes);
    } else {
      await wasm.default();
    }

    const secretKey = opts.secretKey ?? DEFAULT_SECRET_KEY;
    const esploraArr = opts.esploraWasm
      ? new Uint8Array(opts.esploraWasm)
      : undefined;

    const server = new wasm.DevnetServer(
      secretKey,
      opts.alkanesWasm,
      esploraArr,
    );

    return new DevnetTestHarness(
      server,
      opts.interceptUrls ?? DEFAULT_INTERCEPT_URLS,
    );
  }

  /** Current chain height. */
  get height(): number {
    return this.server.height;
  }

  /** Current alkanes indexer height. */
  get indexerHeight(): number {
    return this.server.indexerHeight;
  }

  /** Tip block hash as hex. */
  get tipHashHex(): string {
    return this.server.tipHashHex;
  }

  /** Mine N empty blocks and auto-index through all indexers. */
  mineBlocks(count: number): void {
    this.server.mineBlocks(count);
  }

  /**
   * Process a JSON-RPC request and return the response.
   *
   * This is the low-level entry point — use the fetch interceptor for
   * seamless integration with WebProvider.
   */
  handleRpc(requestJson: string): string {
    return this.server.handleRpc(requestJson);
  }

  /**
   * Install a fetch interceptor that routes JSON-RPC POST requests
   * to the in-process devnet server.
   *
   * After calling this, any `fetch()` to the intercepted URLs will
   * be handled in-process without network access.
   */
  installFetchInterceptor(): void {
    if (this.originalFetch) return; // already installed

    this.originalFetch = globalThis.fetch;
    const self = this;

    const interceptedFetch = function (
      input: RequestInfo | URL,
      init?: RequestInit,
    ): Promise<Response> {
      const url = typeof input === 'string'
        ? input
        : input instanceof URL
          ? input.toString()
          : input.url;

      // Only intercept POST requests to matching URLs
      const method = init?.method?.toUpperCase() ?? 'GET';
      if (method === 'POST' && self.interceptUrls.some(u => url.startsWith(u))) {
        return self.handleFetchRequest(init);
      }

      // Pass through to original fetch
      return self.originalFetch!.call(globalThis, input, init);
    } as typeof globalThis.fetch;

    globalThis.fetch = interceptedFetch;

    // Also override window.fetch — the WASM SDK uses window.fetch
    // which is a separate reference set during vitest setup
    if (typeof globalThis !== 'undefined' && (globalThis as any).window) {
      (globalThis as any).window.fetch = interceptedFetch;
    }
  }

  /** Restore the original fetch function. */
  restoreFetch(): void {
    if (this.originalFetch) {
      globalThis.fetch = this.originalFetch;
      if (typeof globalThis !== 'undefined' && (globalThis as any).window) {
        (globalThis as any).window.fetch = this.originalFetch;
      }
      this.originalFetch = null;
    }
  }

  /** Clean up: restore fetch and free WASM resources. */
  dispose(): void {
    this.restoreFetch();
    // DevnetServer is freed when GC collects it (wasm-bindgen destructor)
  }

  // -- Private ---------------------------------------------------------------

  private async handleFetchRequest(init?: RequestInit): Promise<Response> {
    let bodyText: string;

    if (typeof init?.body === 'string') {
      bodyText = init.body;
    } else if (init?.body instanceof ArrayBuffer) {
      bodyText = new TextDecoder().decode(init.body);
    } else if (init?.body instanceof Uint8Array) {
      bodyText = new TextDecoder().decode(init.body);
    } else {
      // ReadableStream or other — read it
      const resp = new Response(init?.body);
      bodyText = await resp.text();
    }

    try {
      const responseJson = this.server.handleRpc(bodyText);
      return new Response(responseJson, {
        status: 200,
        headers: { 'Content-Type': 'application/json' },
      });
    } catch (e) {
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
}
