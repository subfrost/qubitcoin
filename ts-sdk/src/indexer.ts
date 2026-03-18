import type { SecondaryIndexer as WasmIndexer } from './wasm/qubitcoin_web_sys.js';

/**
 * Secondary indexer runtime wrapper.
 *
 * Manages a metashrew-compatible WASM indexer module running
 * in-process alongside the Qubitcoin devnet node.
 *
 * ```ts
 * const indexer = await IndexerRuntime.load(wasmBytes);
 * indexer.processBlock(blockData);
 * const result = indexer.callView('balanceOf', input);
 * ```
 */
export class IndexerRuntime {
  private inner: WasmIndexer;

  private constructor(inner: WasmIndexer) {
    this.inner = inner;
  }

  /**
   * Load and compile a WASM indexer module from bytes.
   *
   * The module must export a `_start()` function (metashrew ABI).
   */
  static async load(wasmBytes: Uint8Array): Promise<IndexerRuntime> {
    const wasm = await import('./wasm/qubitcoin_web_sys.js');
    await wasm.default();

    const inner = new wasm.SecondaryIndexer(wasmBytes);
    return new IndexerRuntime(inner);
  }

  /** Current indexer tip height. */
  get height(): number {
    return this.inner.height;
  }

  /**
   * Feed a block to the indexer for processing.
   *
   * The block must be in Bitcoin wire format (the same bytes returned
   * by `QubitcoinNode.mineBlock().data`).
   */
  processBlock(blockData: Uint8Array): void {
    this.inner.processBlock(blockData);
  }

  /**
   * Call a named view function on the indexer.
   *
   * Returns the raw result bytes. Interpretation depends on the
   * specific indexer module.
   */
  callView(name: string, input: Uint8Array): Uint8Array {
    return this.inner.callView(name, input);
  }

  /** Compute the sparse Merkle tree state root. */
  stateRoot(): Uint8Array {
    return this.inner.stateRoot();
  }

  /**
   * Roll back the indexer state to a previous height.
   *
   * Returns the number of deleted entries.
   */
  rollbackTo(targetHeight: number): number {
    return this.inner.rollbackTo(targetHeight);
  }

  /** Release WASM resources. */
  dispose(): void {
    this.inner.free();
  }
}
