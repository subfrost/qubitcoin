/** Raw block data with parsed metadata. */
export interface Block {
    /** Block height in the chain. */
    height: number;
    /** Block hash as hex string. */
    hash: string;
    /** Raw block in Bitcoin wire format. */
    data: Uint8Array;
}
/** A spendable UTXO. */
export interface SpendableOutput {
    /** Transaction ID (32 bytes). */
    txid: Uint8Array;
    /** Output index. */
    vout: number;
    /** Value in satoshis. */
    valueSat: number;
}
/** Configuration for creating a QubitcoinNode. */
export interface NodeConfig {
    /** 32-byte secret key for the coinbase recipient. If omitted, a default key is used. */
    secretKey?: Uint8Array;
}
//# sourceMappingURL=types.d.ts.map