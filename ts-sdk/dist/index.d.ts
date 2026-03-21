/**
 * @qubitcoin/sdk — TypeScript SDK for Qubitcoin.
 *
 * Provides a clean wrapper over the qubitcoin-web-sys WASM bindings
 * for in-process devnet operation, chain validation, block processing,
 * and secondary indexer management.
 *
 * @example
 * ```ts
 * import { QubitcoinNode, IndexerRuntime } from '@qubitcoin/sdk';
 *
 * // Start an in-process regtest chain
 * const node = await QubitcoinNode.create();
 *
 * // Mine 101 blocks to mature a coinbase
 * node.mineBlocks(101);
 *
 * // Get a spendable output
 * const utxo = node.getSpendableOutput()!;
 *
 * // Create and mine a transaction
 * const script = QubitcoinNode.buildP2pkhScript(recipientHash);
 * const tx = node.createTransaction(utxo.txid, utxo.vout, 1_000_000, script);
 * node.mineBlockWithTxs([tx]);
 *
 * // Load a secondary indexer
 * const indexer = await IndexerRuntime.load(indexerWasm);
 * for (let h = 0; h <= node.height; h++) {
 *   indexer.processBlock(node.getBlock(h)!.data);
 * }
 * ```
 */
export { QubitcoinNode } from './node.js';
export { IndexerRuntime } from './indexer.js';
export { DevnetTestHarness } from './devnet-server.js';
export type { DevnetTestHarnessOptions, TertiaryIndexerConfig } from './devnet-server.js';
export { LuaRuntime, preloadLuaScripts, saveScript, getScript } from './lua-runtime.js';
export type { RpcHandler } from './lua-runtime.js';
export type { Block, SpendableOutput, NodeConfig } from './types.js';
//# sourceMappingURL=index.d.ts.map