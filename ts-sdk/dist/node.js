// Default secret key (32 bytes of 0x01 — deterministic for testing).
const DEFAULT_SECRET_KEY = new Uint8Array(32).fill(0x01);
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
export class QubitcoinNode {
    devnet;
    constructor(devnet) {
        this.devnet = devnet;
    }
    /**
     * Create and initialize a new in-process regtest node.
     *
     * Automatically loads the WASM module, creates a chain with a genesis
     * block, and returns a ready-to-use node.
     */
    static async create(config) {
        // Dynamic import so the WASM init happens lazily.
        const wasm = await import('./wasm/qubitcoin_web_sys.js');
        await wasm.default();
        const key = config?.secretKey ?? DEFAULT_SECRET_KEY;
        const devnet = new wasm.QubitcoinDevnet(key);
        return new QubitcoinNode(devnet);
    }
    // -- Chain state --------------------------------------------------------
    /** Current chain tip height (0 = genesis only). */
    get height() {
        return this.devnet.height;
    }
    /** Tip block hash as hex string. */
    get tipHash() {
        return this.devnet.tipHashHex;
    }
    /** Tip block hash as raw bytes. */
    get tipHashBytes() {
        return this.devnet.tipHash;
    }
    /** Number of UTXOs in the in-memory set. */
    get utxoCount() {
        return this.devnet.utxoCount;
    }
    /** Coinbase public key (33-byte compressed). */
    get coinbasePubkey() {
        return this.devnet.coinbasePubkey;
    }
    /** Number of mature (spendable) coinbase outputs. */
    get matureCoinbaseCount() {
        return this.devnet.matureCoinbaseCount;
    }
    // -- Mining -------------------------------------------------------------
    /** Mine a single empty block. Returns the mined block. */
    mineBlock() {
        const data = this.devnet.mineBlock();
        return {
            height: this.devnet.height,
            hash: this.devnet.tipHashHex,
            data,
        };
    }
    /** Mine `count` empty blocks. Returns the last mined block. */
    mineBlocks(count) {
        const data = this.devnet.mineBlocks(count);
        return {
            height: this.devnet.height,
            hash: this.devnet.tipHashHex,
            data,
        };
    }
    /**
     * Mine a block containing the given transactions.
     *
     * Each transaction must be in Bitcoin wire format (Uint8Array).
     */
    mineBlockWithTxs(rawTxs) {
        const data = this.devnet.mineBlockWithTxs(rawTxs);
        return {
            height: this.devnet.height,
            hash: this.devnet.tipHashHex,
            data,
        };
    }
    // -- Block queries ------------------------------------------------------
    /** Get a block by height, or `null` if out of range. */
    getBlock(height) {
        const data = this.devnet.getBlock(height);
        if (data === null)
            return null;
        const hash = this.devnet.getBlockHash(height);
        return { height, hash, data };
    }
    /** Get the block hash at a given height as hex, or `null`. */
    getBlockHash(height) {
        return this.devnet.getBlockHash(height);
    }
    // -- Transaction helpers ------------------------------------------------
    /**
     * Create a simple transaction spending a UTXO.
     *
     * Returns the raw serialized transaction (Bitcoin wire format).
     * Change (minus 1000-sat fee) goes back to the coinbase address.
     */
    createTransaction(txid, vout, valueSat, destScript) {
        return this.devnet.createTransaction(txid, vout, valueSat, destScript);
    }
    /**
     * Find the first spendable (mature, unspent) coinbase output.
     *
     * Returns `null` if no coinbase is mature yet (need 100 confirmations).
     */
    getSpendableOutput() {
        return this.devnet.getSpendableOutput();
    }
    // -- UTXO queries -------------------------------------------------------
    /** Check whether a UTXO exists in the set. */
    hasUtxo(txid, vout) {
        return this.devnet.hasUtxo(txid, vout);
    }
    /** Get a UTXO's value in satoshis, or `null` if not found. */
    getUtxoValue(txid, vout) {
        return this.devnet.getUtxoValue(txid, vout);
    }
    // -- Crypto helpers -----------------------------------------------------
    /** Build a P2PKH locking script from a 20-byte pubkey hash. */
    static buildP2pkhScript(pubkeyHash) {
        // Lazy import to avoid needing WASM loaded for static helpers.
        // In practice this works because create() must be called first.
        const wasm = globalThis.__qubitcoin_wasm;
        if (wasm)
            return wasm.QubitcoinDevnet.buildP2pkhScript(pubkeyHash);
        throw new Error('Call QubitcoinNode.create() before using static helpers');
    }
    /** Derive a compressed public key (33 bytes) from a 32-byte secret key. */
    static pubkeyFromSecret(secretKey) {
        const wasm = globalThis.__qubitcoin_wasm;
        if (wasm)
            return wasm.QubitcoinDevnet.pubkeyFromSecret(secretKey);
        throw new Error('Call QubitcoinNode.create() before using static helpers');
    }
    /** Compute Hash160 (RIPEMD160(SHA256(data))). */
    static hash160(data) {
        const wasm = globalThis.__qubitcoin_wasm;
        if (wasm)
            return wasm.QubitcoinDevnet.hash160(data);
        throw new Error('Call QubitcoinNode.create() before using static helpers');
    }
    /** Release WASM resources. Call when done with the node. */
    dispose() {
        this.devnet.free();
    }
}
//# sourceMappingURL=node.js.map