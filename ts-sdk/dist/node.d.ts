import type { Block, SpendableOutput, NodeConfig } from './types.js';
/**
 * In-process Qubitcoin regtest node.
 *
 * Wraps the qubitcoin-web-sys WASM module to provide a high-level
 * TypeScript interface for chain operations — the qubitcoin equivalent
 * of hardhat's in-process node or ganache.
 *
 * ```ts
 * import { QubitcoinNode } from '@qubitcoin/sdk';
 * const node = await QubitcoinNode.create();
 * node.mineBlocks(101); // mature a coinbase
 * const utxo = node.getSpendableOutput();
 * ```
 */
export declare class QubitcoinNode {
    private devnet;
    private constructor();
    /**
     * Create and initialize a new in-process regtest node.
     *
     * Automatically loads the WASM module, creates a chain with a genesis
     * block, and returns a ready-to-use node.
     */
    static create(config?: NodeConfig): Promise<QubitcoinNode>;
    /** Current chain tip height (0 = genesis only). */
    get height(): number;
    /** Tip block hash as hex string. */
    get tipHash(): string;
    /** Tip block hash as raw bytes. */
    get tipHashBytes(): Uint8Array;
    /** Number of UTXOs in the in-memory set. */
    get utxoCount(): number;
    /** Coinbase public key (33-byte compressed). */
    get coinbasePubkey(): Uint8Array;
    /** Number of mature (spendable) coinbase outputs. */
    get matureCoinbaseCount(): number;
    /** Mine a single empty block. Returns the mined block. */
    mineBlock(): Block;
    /** Mine `count` empty blocks. Returns the last mined block. */
    mineBlocks(count: number): Block;
    /**
     * Mine a block containing the given transactions.
     *
     * Each transaction must be in Bitcoin wire format (Uint8Array).
     */
    mineBlockWithTxs(rawTxs: Uint8Array[]): Block;
    /** Get a block by height, or `null` if out of range. */
    getBlock(height: number): Block | null;
    /** Get the block hash at a given height as hex, or `null`. */
    getBlockHash(height: number): string | null;
    /**
     * Create a simple transaction spending a UTXO.
     *
     * Returns the raw serialized transaction (Bitcoin wire format).
     * Change (minus 1000-sat fee) goes back to the coinbase address.
     */
    createTransaction(txid: Uint8Array, vout: number, valueSat: number, destScript: Uint8Array): Uint8Array;
    /**
     * Find the first spendable (mature, unspent) coinbase output.
     *
     * Returns `null` if no coinbase is mature yet (need 100 confirmations).
     */
    getSpendableOutput(): SpendableOutput | null;
    /** Check whether a UTXO exists in the set. */
    hasUtxo(txid: Uint8Array, vout: number): boolean;
    /** Get a UTXO's value in satoshis, or `null` if not found. */
    getUtxoValue(txid: Uint8Array, vout: number): number | null;
    /** Build a P2PKH locking script from a 20-byte pubkey hash. */
    static buildP2pkhScript(pubkeyHash: Uint8Array): Uint8Array;
    /** Derive a compressed public key (33 bytes) from a 32-byte secret key. */
    static pubkeyFromSecret(secretKey: Uint8Array): Uint8Array;
    /** Compute Hash160 (RIPEMD160(SHA256(data))). */
    static hash160(data: Uint8Array): Uint8Array;
    /** Release WASM resources. Call when done with the node. */
    dispose(): void;
}
//# sourceMappingURL=node.d.ts.map