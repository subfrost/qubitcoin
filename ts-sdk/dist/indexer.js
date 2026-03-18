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
    inner;
    constructor(inner) {
        this.inner = inner;
    }
    /**
     * Load and compile a WASM indexer module from bytes.
     *
     * The module must export a `_start()` function (metashrew ABI).
     */
    static async load(wasmBytes) {
        const wasm = await import('./wasm/qubitcoin_web_sys.js');
        await wasm.default();
        const inner = new wasm.SecondaryIndexer(wasmBytes);
        return new IndexerRuntime(inner);
    }
    /** Current indexer tip height. */
    get height() {
        return this.inner.height;
    }
    /**
     * Feed a block to the indexer for processing.
     *
     * The block must be in Bitcoin wire format (the same bytes returned
     * by `QubitcoinNode.mineBlock().data`).
     */
    processBlock(blockData) {
        this.inner.processBlock(blockData);
    }
    /**
     * Call a named view function on the indexer.
     *
     * `height` is the block height context for the view call.
     * Returns the raw result bytes. Interpretation depends on the
     * specific indexer module.
     */
    callView(name, height, input) {
        return this.inner.callView(name, height, input);
    }
    /** Compute the sparse Merkle tree state root. */
    stateRoot() {
        return this.inner.stateRoot();
    }
    /**
     * Roll back the indexer state to a previous height.
     *
     * Returns the number of deleted entries.
     */
    rollbackTo(targetHeight) {
        return this.inner.rollbackTo(targetHeight);
    }
    /** Release WASM resources. */
    dispose() {
        this.inner.free();
    }
}
//# sourceMappingURL=indexer.js.map