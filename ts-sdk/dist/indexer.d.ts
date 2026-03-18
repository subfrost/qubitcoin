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
export declare class IndexerRuntime {
    private inner;
    private constructor();
    /**
     * Load and compile a WASM indexer module from bytes.
     *
     * The module must export a `_start()` function (metashrew ABI).
     */
    static load(wasmBytes: Uint8Array): Promise<IndexerRuntime>;
    /** Current indexer tip height. */
    get height(): number;
    /**
     * Feed a block to the indexer for processing.
     *
     * The block must be in Bitcoin wire format (the same bytes returned
     * by `QubitcoinNode.mineBlock().data`).
     */
    processBlock(blockData: Uint8Array): void;
    /**
     * Call a named view function on the indexer.
     *
     * `height` is the block height context for the view call.
     * Returns the raw result bytes. Interpretation depends on the
     * specific indexer module.
     */
    callView(name: string, height: number, input: Uint8Array): Uint8Array;
    /** Compute the sparse Merkle tree state root. */
    stateRoot(): Uint8Array;
    /**
     * Roll back the indexer state to a previous height.
     *
     * Returns the number of deleted entries.
     */
    rollbackTo(targetHeight: number): number;
    /** Release WASM resources. */
    dispose(): void;
}
//# sourceMappingURL=indexer.d.ts.map